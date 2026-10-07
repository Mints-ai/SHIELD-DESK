import { NextRequest, NextResponse } from "next/server";
import { getHibpApiKey, getHibpStatus } from "@/lib/hibp";

export async function GET() {
  const status = getHibpStatus();
  return NextResponse.json(status);
}
