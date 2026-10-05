import type { Metadata } from "next";
import { ChatWidget } from "@/components/ai-chat/ChatWidget";
import { ChatProvider } from "@/lib/context/ChatContext";
import "./globals.css";

const themeInitializationScript = "try{document.documentElement.dataset.theme=localStorage.getItem('shielddesk-theme')==='dark'?'dark':'light'}catch{}";

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
    <html lang="en" data-theme="light" className="h-full antialiased" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitializationScript }} />
      </head>
      <body className="sd-scene min-h-full flex flex-col bg-[var(--sd-bg)] text-foreground" suppressHydrationWarning>
        <ChatProvider>
          {children}
          {/* Globally-available floating entry point */}
          <ChatWidget />
        </ChatProvider>
      </body>
    </html>
  );
}
