import { NextRequest, NextResponse } from "next/server";
import { ollama, OLLAMA_MODEL } from "@/lib/ai/ollama";
import { getSessionFromRequest, type ChatSession } from "@/lib/auth/session";
import { getSupabase } from "@/lib/db";
import {
  CHAT_TOOLS,
  getIncidents,
  investigateIncident,
  analyzeCve,
  generateMitigationPlan,
} from "@/lib/tools";
/**
 * POST /api/chat
 *
 * The model (a local Ollama instance) is a constrained intent router (see
 * Scope Addendum) across exactly four tools. Two paths decide which tool
 * runs:
 *
 *   Path A — the message itself contains enough structure to route
 *            deterministically (a CVE id, an incident code, "mitigation
 *            plan", etc.) → skip the model entirely for tool selection.
 *   Path B — everything else → ask the model to pick one of the four
 *            tools, with tool_choice "auto" so it can also decline (no
 *            tool call = out of scope), rather than answering from its
 *            own general knowledge.
 *
 * lf.The model never touches Postgres or the Python AI engine directly —
 * every tool call below goes through lib/tools, which re-checks RBAC +
 * tenant isolation itse
 */

const MAX_MESSAGE_LENGTH = 4000;

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i;
const INCIDENT_ID_RE = /\bINC-\d+\b/i;
const MITIGATION_RE = /\bmitigation\b/i;
const SEVERITY_RE = /\b(critical|high|medium|low)\b/i;
const STATUS_RE = /\b(open|investigating|resolved|closed)\b/i;
const INCIDENTS_WORD_RE = /\bincidents?\b/i;

type ToolName =
  | "getIncidents"
  | "investigateIncident"
  | "analyzeCve"
  | "generateMitigationPlan";

const ROUTING_SYSTEM_PROMPT = `You are ShieldDesk's request router. You support
exactly four capabilities: fetching incidents, analyzing a CVE, investigating
a specific incident, and generating a mitigation plan for an incident.

Call the matching tool for any request about incidents, vulnerabilities, or
mitigation. If the request is about anything else — general security
questions, small talk, unrelated topics — do NOT call any tool. Do not guess
which tool is closest; simply decline.`;

const FORMAT_SYSTEM_PROMPT = `You are the ShieldDesk AI Chat Widget. Use the
provided tool result data to answer the user's question directly, accurately,
and concisely.

Do NOT output JSON or raw field names. Do NOT use Markdown formatting of any
kind — no bold, no bullet dashes, no headers, no backticks — the chat UI
displays plain text only. Use plain sentences, or a simple numbered list
("1. ", "2. ") for multiple separate items (multiple incidents, multiple
assets).

Always note that this is a recommendation/analysis, not an executed action,
when the data includes a mitigation plan or governance note.`;

const ERROR_MESSAGES: Record<string, string> = {
  not_found: "I couldn't find that — double check the ID and try again.",
  not_authorized: "You don't have permission to view that.",
  missing_incident_id: "I need an incident ID (e.g. INC-1042) to do that.",
  missing_cve_id: "I need a CVE ID (e.g. CVE-2024-3400) to do that.",
  engine_not_configured:
    "The vulnerability-intelligence engine isn't configured yet.",
  engine_unavailable:
    "The vulnerability-intelligence engine is temporarily unavailable — try again shortly.",
  engine_error: "The vulnerability-intelligence engine returned an error.",
  data_unavailable: "I couldn't reach the database just now — try again shortly.",
};

async function runTool(
  name: ToolName,
  session: ChatSession,
  args: Record<string, unknown>
) {
  switch (name) {
    case "getIncidents":
      return getIncidents(session, args);
    case "investigateIncident":
      return investigateIncident(session, args);
    case "analyzeCve":
      return analyzeCve(session, args);
    case "generateMitigationPlan":
      return generateMitigationPlan(session, args);
  }
}

function sseHeaders() {
  return {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  };
}

/** Streams a single fixed message as SSE — used for out-of-scope + error replies. */
function streamFixedMessage(
  message: string,
  audit: { session: ChatSession; question: string; toolName: string | null; outcome: string }
) {
  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ token: message })}\n\n`));
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      controller.close();
      logAudit({ ...audit, answer: message });
    },
  });
  return new Response(readable, { headers: sseHeaders() });
}

function logAudit(entry: {
  session: ChatSession;
  question: string;
  toolName: string | null;
  outcome: string;
  answer: string;
}) {
  // Fire-and-forget — never blocks the response on the audit write.
  void Promise.resolve(
    getSupabase()
      .from("chat_audit_log")
      .insert({
        uid: entry.session.uid,
        role: entry.session.role,
        tenant_id: entry.session.tenantId,
        question: entry.question,
        tool_called: entry.toolName,
        answer: entry.answer,
        outcome: entry.outcome,
      })
  ).then(({ error }) => {
    if (error) console.error("Audit log error:", error);
  }).catch((err: unknown) => {
    console.error("Audit log error:", err);
  });
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  let body: { message?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const message = body?.message;
  if (!message || typeof message !== "string") {
    return NextResponse.json(
      { error: "`message` is required and must be a string." },
      { status: 400 }
    );
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    return NextResponse.json(
      { error: `Message is too long (max ${MAX_MESSAGE_LENGTH} characters).` },
      { status: 413 }
    );
  }

  let toolName: ToolName | null = null;
  let toolArgs: Record<string, unknown> = {};
  let outOfScope = false;

  const cveMatch = message.match(CVE_RE);
  const incidentMatch = message.match(INCIDENT_ID_RE);

  // --- Path A: deterministic routing from message structure ---
  if (cveMatch) {
    toolName = "analyzeCve";
    toolArgs = { cveId: cveMatch[0].toUpperCase() };
  } else if (MITIGATION_RE.test(message) && incidentMatch) {
    toolName = "generateMitigationPlan";
    toolArgs = { incidentId: incidentMatch[0].toUpperCase() };
  } else if (incidentMatch) {
    toolName = "investigateIncident";
    toolArgs = { incidentId: incidentMatch[0].toUpperCase() };
  } else if (INCIDENTS_WORD_RE.test(message)) {
    toolName = "getIncidents";
    const severity = message.match(SEVERITY_RE)?.[1]?.toLowerCase();
    const status = message.match(STATUS_RE)?.[1]?.toLowerCase();
    toolArgs = {
      ...(severity ? { severity } : {}),
      ...(status ? { status } : {}),
    };
  } else {
    // --- Path B: let the model pick a tool, or genuinely decline ---
    try {
      const completion = await ollama.chat.completions.create({
        model: OLLAMA_MODEL,
        messages: [
          { role: "system", content: ROUTING_SYSTEM_PROMPT },
          { role: "user", content: message },
        ],
        tools: CHAT_TOOLS,
        tool_choice: "auto",
      });

      const call = completion.choices[0]?.message?.tool_calls?.[0];
      if (call && call.type === "function") {
        toolName = call.function.name as ToolName;
        try {
          toolArgs = JSON.parse(call.function.arguments || "{}");
        } catch {
          toolArgs = {};
        }
      } else {
        outOfScope = true;
      }
    } catch {
      return streamFixedMessage(
        "I couldn't reach the local assistant model just now — check that " +
          "Ollama is running and try again.",
        { session, question: message, toolName: null, outcome: "model_unavailable" }
      );
    }
  }

  if (outOfScope) {
    return streamFixedMessage(
      "That's outside what I can help with here. I can fetch incidents, " +
        "analyze a CVE, investigate an incident, or generate a mitigation plan.",
      { session, question: message, toolName: null, outcome: "out_of_scope" }
    );
  }

  const toolResult = await runTool(toolName!, session, toolArgs);

  if (toolResult && typeof toolResult === "object" && "error" in toolResult) {
    const code = (toolResult as { error: string }).error;
    const fixed = ERROR_MESSAGES[code] ?? "I couldn't complete that request.";
    return streamFixedMessage(fixed, {
      session,
      question: message,
      toolName,
      outcome: code,
    });
  }

  // --- Stream the final natural-language answer ---
  let stream;
  try {
    stream = await ollama.chat.completions.create({
      model: OLLAMA_MODEL,
      stream: true,
      messages: [
        {
          role: "system",
          content: `${FORMAT_SYSTEM_PROMPT}\n\nTool result (JSON): ${JSON.stringify(toolResult)}`,
        },
        { role: "user", content: message },
      ],
    });
  } catch {
    return streamFixedMessage(
      "I couldn't reach the local assistant model just now — check that " +
        "Ollama is running and try again.",
      { session, question: message, toolName, outcome: "model_unavailable" }
    );
  }

  let fullAnswer = "";
  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    async start(controller) {
      try {
        for await (const chunk of stream) {
          const token = chunk.choices[0]?.delta?.content;
          if (token) {
            fullAnswer += token;
            controller.enqueue(encoder.encode(`data: ${JSON.stringify({ token })}\n\n`));
          }
        }
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      } catch (err) {
        console.error("Stream error:", err);
      } finally {
        controller.close();
        logAudit({
          session,
          question: message,
          toolName,
          outcome: "authorized",
          answer: fullAnswer,
        });
      }
    },
  });

  return new Response(readable, { headers: sseHeaders() });
}
