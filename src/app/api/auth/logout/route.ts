import { NextResponse } from "next/server";
import { trackError } from "@/lib/observability/errorTracker";

export async function POST() {
  try {
    const res = NextResponse.json({ success: true, message: "Logged out" });
    res.cookies.delete("shielddesk_session");
    return res;
  } catch (err) {
    trackError(err, { route: "POST /api/auth/logout" });
    return NextResponse.json({ error: "Failed to logout" }, { status: 500 });
  }
}
