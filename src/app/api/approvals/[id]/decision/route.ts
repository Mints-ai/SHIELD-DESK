import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { approveActionToken, rejectActionToken } from "@/lib/governance/approvalTokens";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "missing_token_id" }, { status: 400 });
  }

  try {
    const body = await req.json();
    const action = body.action; // "approve" | "reject"

    if (action === "approve") {
      const result = await approveActionToken(session, { tokenId: id });
      if ("error" in result) {
        const status =
          result.error === "not_found"
            ? 404
            : result.error === "separation_of_duties_violation"
              ? 403
              : 400;
        return NextResponse.json(result, { status });
      }
      return NextResponse.json(result);
    } else if (action === "reject") {
      const result = await rejectActionToken(session, {
        tokenId: id,
        reason: body.reason,
      });
      if ("error" in result) {
        const status = result.error === "not_found" ? 404 : 400;
        return NextResponse.json(result, { status });
      }
      return NextResponse.json(result);
    }

    return NextResponse.json(
      { error: "Invalid action. Must be 'approve' or 'reject'." },
      { status: 400 }
    );
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
}
