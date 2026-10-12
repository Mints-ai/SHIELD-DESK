import type { Metadata } from "next";
import { Sora, Orbitron, Space_Grotesk } from "next/font/google";
import { ChatWidget } from "@/components/ai-chat/ChatWidget";
import { ChatProvider } from "@/lib/context/ChatContext";
import "./globals.css";

const sora = Sora({
  subsets: ["latin"],
  variable: "--font-sora",
  display: "swap",
  weight: ["300", "400", "500", "600", "700"],
});

const orbitron = Orbitron({
  subsets: ["latin"],
  variable: "--font-orbitron",
  display: "swap",
  weight: ["400", "500", "600", "700", "800", "900"],
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  display: "swap",
  weight: ["300", "400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "ShieldDesk™ — AI-Powered Security Operations | Mints Global",
  description: "Autonomous Security Operations Center co-pilot and incident orchestration platform by Mints Global.",
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/favicon/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon/favicon-16x16.png", sizes: "16x16", type: "image/png" },
    ],
    apple: "/favicon/apple-touch-icon.png",
  },
  manifest: "/favicon/site.webmanifest",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      data-theme="dark"
      className={`h-full antialiased ${sora.variable} ${orbitron.variable} ${spaceGrotesk.variable}`}
      suppressHydrationWarning
    >
      <body className="sd-scene min-h-full flex flex-col bg-[var(--sd-bg)] text-foreground font-sans" suppressHydrationWarning>
        <ChatProvider>
          {children}
          {/* Globally-available floating entry point */}
          <ChatWidget />
        </ChatProvider>
      </body>
    </html>
  );
}
