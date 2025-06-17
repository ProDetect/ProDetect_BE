
import './logger.ts';
import { StrictMode, useEffect, useState, useRef, createContext, lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import Fallback from "./Fallback.tsx";
import SystemErrorBoundary from "./SystemErrorBoundary.tsx";
import "./index.css";
import ScreenshotComponent from "./components/ScreenshotComponent.tsx";
import Router from "./components/Router.tsx";
import { client } from './lib/sdk/client.gen';
client.setConfig({ 
  baseUrl: "https://" + window.location.hostname.replace("5173", "8000"),
});
import { AuthProvider } from "@/auth/AuthProvider.tsx";

export const AuthTokenContext = createContext<string | null>(null);
const Root = () => {
  Element.prototype.scrollIntoView = function() { return false; };
  Element.prototype.scrollTo = function() { return false; };
  Element.prototype.scrollBy = function() { return false; };

  return (
    <>
      <AuthProvider
          client={client}
          clientId={"4ce84566-97c4-49b7-b228-521b12683573"}
          baseInfranodeUrl={"api.solarapp.dev"}
          loginRedirectUrl={"https://solarapp.dev/external-login"}
          appName={"App Name"}
      >
        <BrowserRouter>
          <Routes>
            <Route path="*" element={
              <SystemErrorBoundary viewName="Fallback">
                <Suspense fallback={<div>Loading...</div>}>
                  <Router />
                </Suspense>
              </SystemErrorBoundary>
            } />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
      <ScreenshotComponent />
    </>
  )
}

createRoot(document.getElementById("root")).render(<Root />);