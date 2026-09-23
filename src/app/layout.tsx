import type { Metadata } from "next";
import { ChatWidget } from "@/components/ai-chat/ChatWidget";
import { ChatProvider } from "@/lib/context/ChatContext";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShieldDesk™ — AI-Powered Security Operations | Mints Global",
  description: "Autonomous Security Operations Center co-pilot and incident orchestration platform by Mints Global.",
  icons: {
    icon: "/logo.png",
    apple: "/logo.png",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-full flex flex-col bg-[var(--sd-bg)] text-foreground selection:bg-[var(--sd-pine)] selection:text-[#f7f4ed]" suppressHydrationWarning>
        <ChatProvider>
          {children}
          {/* Globally-available floating entry point */}
          <ChatWidget />
        </ChatProvider>
      </body>
    </html>
  );
}
