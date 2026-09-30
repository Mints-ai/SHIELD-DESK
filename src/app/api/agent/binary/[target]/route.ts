import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";

const TARGET_MAP: Record<string, { filename: string; mime: string }> = {
  "windows-amd64": { filename: "shielddesk-agent-windows-amd64.exe", mime: "application/vnd.microsoft.portable-executable" },
  "linux-amd64": { filename: "shielddesk-agent-linux-amd64", mime: "application/octet-stream" },
  "linux-arm64": { filename: "shielddesk-agent-linux-arm64", mime: "application/octet-stream" },
  "darwin-arm64": { filename: "shielddesk-agent-darwin-arm64", mime: "application/octet-stream" },
};

/**
 * GET /api/agent/binary/[target]
 * Public download route for pre-compiled ShieldDesk Universal Endpoint Agent binaries.
 * Targets: windows-amd64, linux-amd64, linux-arm64, darwin-arm64
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ target: string }> }
) {
  const { target } = await params;
  const config = TARGET_MAP[target];

  if (!config) {
    return NextResponse.json(
      { error: `Unsupported target platform '${target}'. Available: ${Object.keys(TARGET_MAP).join(", ")}` },
      { status: 400 }
    );
  }

  const binaryPath = path.resolve(process.cwd(), "agent", "bin", config.filename);

  if (!fs.existsSync(binaryPath)) {
    return NextResponse.json(
      {
        error: `Binary for target '${target}' is not yet compiled on this server. Run 'agent/scripts/build-cross-platform.ps1' or '.sh'.`,
        code: "BINARY_NOT_FOUND",
      },
      { status: 404 }
    );
  }

  const fileBuffer = fs.readFileSync(binaryPath);
  return new NextResponse(fileBuffer, {
    status: 200,
    headers: {
      "Content-Type": config.mime,
      "Content-Disposition": `attachment; filename="${config.filename}"`,
      "Content-Length": String(fileBuffer.length),
      "Cache-Control": "public, max-age=3600",
    },
  });
}
