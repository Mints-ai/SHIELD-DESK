"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";

import { DEV_USERS, type DevUserId, type DevUserMetadata } from "@/lib/constants/devUsers";
import { SIGNED_OUT_OPERATOR, type OperatorIdentity } from "@/lib/auth/operatorIdentity";
export { DEV_USERS, type DevUserId, type DevUserMetadata };

interface ChatContextType {
  activeUserId: string;
  setActiveUserId: (id: DevUserId) => void;
  activeUser: OperatorIdentity;
  devPersonasAllowed: boolean;
  isIdentityLoading: boolean;
  refreshSession: () => Promise<void>;
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
  const [activeUser, setActiveUser] = useState<OperatorIdentity>(SIGNED_OUT_OPERATOR);
  const [devPersonasAllowed, setDevPersonasAllowed] = useState(false);
  const [isIdentityLoading, setIsIdentityLoading] = useState(true);
  const [activeIncidentId, setActiveIncidentIdState] = useState<string | null>(null);
  const requestRef = useRef<AbortController | null>(null);
  const activeUserId = activeUser.id;
  const refreshSession = useCallback(() => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    return Promise.resolve().then(() => fetch("/api/auth/session", {
      cache: "no-store", credentials: "same-origin", signal: controller.signal,
    })).then(async (response) => {
      const result = await response.json();
      if (controller.signal.aborted) return;
      try {
        const savedIncident = sessionStorage.getItem(STORAGE_KEY_INCIDENT);
        if (savedIncident && savedIncident !== "undefined" && savedIncident !== "null" && savedIncident.trim() !== "") {
          setActiveIncidentIdState(savedIncident.trim());
        }
      } catch { /* unavailable storage */ }
      if (!response.ok && response.status !== 401) throw new Error("Session could not be verified");
      const allowPersonas = result.devPersonasAllowed === true;
      setDevPersonasAllowed(allowPersonas);
      if (allowPersonas) {
        let saved: string | null = null;
        try { saved = sessionStorage.getItem(STORAGE_KEY_USER); } catch { /* unavailable storage */ }
        const persona = saved && Object.hasOwn(DEV_USERS, saved) ? saved as DevUserId
          : result.user?.id && Object.hasOwn(DEV_USERS, result.user.id) ? result.user.id as DevUserId : "dev-analyst";
        setActiveUser(DEV_USERS[persona]);
      } else {
        setActiveUser(result.user || SIGNED_OUT_OPERATOR);
      }
    }).catch(() => {
      if (!controller.signal.aborted) { setActiveUser(SIGNED_OUT_OPERATOR); setDevPersonasAllowed(false); }
    }).finally(() => {
      if (!controller.signal.aborted) setIsIdentityLoading(false);
    });
  }, []);
  const [activeCveId, setActiveCveId] = useState<string | null>(null);
  const [isChatOpen, setIsChatOpen] = useState<boolean>(false);
  const [promptToInject, setPromptToInject] = useState<string | null>(null);

  useEffect(() => {
    void refreshSession();
    const refresh = () => { void refreshSession(); };
    window.addEventListener("shielddesk:session-changed", refresh);
    return () => { requestRef.current?.abort(); window.removeEventListener("shielddesk:session-changed", refresh); };
  }, [refreshSession]);

  const setActiveUserId = (id: DevUserId) => {
    if (!devPersonasAllowed || !Object.hasOwn(DEV_USERS, id)) return;
    setActiveUser(DEV_USERS[id]);
    try {
      sessionStorage.setItem(STORAGE_KEY_USER, id);
    } catch {
      // ignore
    }
  };

  const setActiveIncidentId = (id: string | null) => {
    const cleanId = id && id !== "undefined" && id !== "null" && id.trim() !== "" ? id.trim() : null;
    setActiveIncidentIdState(cleanId);
    try {
      if (cleanId) {
        sessionStorage.setItem(STORAGE_KEY_INCIDENT, cleanId);
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


  return (
    <ChatContext.Provider
      value={{
        activeUserId,
        setActiveUserId,
        activeUser,
        devPersonasAllowed,
        isIdentityLoading,
        refreshSession,
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
