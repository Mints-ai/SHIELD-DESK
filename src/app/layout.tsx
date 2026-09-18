import type { Metadata } from "next";
import { ChatWidget } from "@/components/ai-chat/ChatWidget";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShieldDesk",
  description: "ShieldDesk AI-SOC platform",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <body className="min-h-full flex flex-col" suppressHydrationWarning>
        {children}
        {/* Globally-available floating entry point */}
        <ChatWidget />
      </body>
    </html>
  );
}
