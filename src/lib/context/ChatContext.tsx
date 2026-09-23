"use client";

import React, { createContext, useContext, useState, useEffect } from "react";

import { DEV_USERS, type DevUserId, type DevUserMetadata } from "@/lib/constants/devUsers";
export { DEV_USERS, type DevUserId, type DevUserMetadata };

interface ChatContextType {
  activeUserId: DevUserId;
  setActiveUserId: (id: DevUserId) => void;
  activeUser: DevUserMetadata;
  activeIncidentId: string | null;
  setActiveIncidentId: (id: string | null) => void;
  activeCveId: string | null;
  setActiveCveId: (id: string | null) => void;
  isChatOpen: boolean;
  setIsChatOpen: (open: boolean) => void;
  promptToInject: string | null;
  setPromptToInject: (prompt: string | null) => void;
  openChatWithPrompt: (prompt: string, incidentId?: string) => void;
}

const ChatContext = createContext<ChatContextType | undefined>(undefined);

const STORAGE_KEY_USER = "shielddesk_active_user_id";
const STORAGE_KEY_INCIDENT = "shielddesk_active_incident_id";

export function ChatProvider({ children }: { children: React.ReactNode }) {
  const [activeUserId, setActiveUserIdState] = useState<DevUserId>("dev-analyst");
  const [activeIncidentId, setActiveIncidentIdState] = useState<string | null>(null);
  const [activeCveId, setActiveCveId] = useState<string | null>(null);
  const [isChatOpen, setIsChatOpen] = useState<boolean>(false);
  const [promptToInject, setPromptToInject] = useState<string | null>(null);

  useEffect(() => {
    try {
      const savedUser = sessionStorage.getItem(STORAGE_KEY_USER) as DevUserId | null;
      if (savedUser && DEV_USERS[savedUser]) {
        setActiveUserIdState(savedUser);
      }
      const savedIncident = sessionStorage.getItem(STORAGE_KEY_INCIDENT);
      if (savedIncident) {
        setActiveIncidentIdState(savedIncident);
      }
    } catch {
      // sessionStorage not available or SSR
    }
  }, []);

  const setActiveUserId = (id: DevUserId) => {
    setActiveUserIdState(id);
    try {
      sessionStorage.setItem(STORAGE_KEY_USER, id);
    } catch {
      // ignore
    }
  };

  const setActiveIncidentId = (id: string | null) => {
    setActiveIncidentIdState(id);
    try {
      if (id) {
        sessionStorage.setItem(STORAGE_KEY_INCIDENT, id);
      } else {
        sessionStorage.removeItem(STORAGE_KEY_INCIDENT);
      }
    } catch {
      // ignore
    }
  };

  const openChatWithPrompt = (prompt: string, incidentId?: string) => {
    if (incidentId) {
      setActiveIncidentId(incidentId);
    }
    setPromptToInject(prompt);
    setIsChatOpen(true);
  };

  const activeUser = DEV_USERS[activeUserId] || DEV_USERS["dev-analyst"];

  return (
    <ChatContext.Provider
      value={{
        activeUserId,
        setActiveUserId,
        activeUser,
        activeIncidentId,
        setActiveIncidentId,
        activeCveId,
        setActiveCveId,
        isChatOpen,
        setIsChatOpen,
        promptToInject,
        setPromptToInject,
        openChatWithPrompt,
      }}
    >
      {children}
    </ChatContext.Provider>
  );
}

export function useChat() {
  const context = useContext(ChatContext);
  if (!context) {
    throw new Error("useChat must be used within a ChatProvider");
  }
  return context;
}
