import { useCallback, useEffect, useState, useRef } from "react";
interface UserDetails {
    active: boolean;
    client_id: string;
    sub: string;
    email: string;
}

interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    status?: string;
    message?: string;
}

interface AuthState {
    isLoggedIn: boolean;
    userDetails: UserDetails | null;
    authLoading: boolean;
    token: string | null;
    login: () => Promise<void>;
    logout: () => void;
}

const STORAGE_KEYS = {
    CODE_VERIFIER: "solar_oauth_code_verifier",
};

const memoryTokens: {
    accessToken: string | null;
    expiry: number | null;
} = {
    accessToken: null,
    expiry: null
};

const storage = {
    get: (key: string) => localStorage.getItem(key),
    set: (key: string, value: string) => localStorage.setItem(key, value),
    remove: (key: string) => localStorage.removeItem(key),
    getAccessToken: () => memoryTokens.accessToken,
    getTokenExpiry: () => memoryTokens.expiry,
    setAccessToken: (token: string, expiresIn: number) => {
        memoryTokens.accessToken = token;
        memoryTokens.expiry = Date.now() + (expiresIn * 1000);
    },
    clearAuth: () => {
        memoryTokens.accessToken = null;
        memoryTokens.expiry = null;
    }
};

const generateRandomString = (length: number): string => {
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    return Array.from({ length }, () => charset.charAt(Math.floor(Math.random() * charset.length))).join("");
};

const createCodeChallenge = async (codeVerifier: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await window.crypto.subtle.digest("SHA-256", data);

    return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
};

const extractJwtId = (token: string): string | null => {
    try {
        const [, payloadBase64] = token.split(".");
        if (!payloadBase64) return null;

        const payload = JSON.parse(atob(payloadBase64));
        return payload.jti || null;
    } catch (error) {
        return null;
    }
};

export function useAuth(
    baseUrl: string,
    baseInfranodeUrl: string,
    loginRedirectUrl = "http://localhost:4000/external-login",
    clientId: string = crypto.randomUUID()
): AuthState {
    const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
    const [userDetails, setUserDetails] = useState<UserDetails | null>(null);
    const [authLoading, setAuthLoading] = useState<boolean>(true);
    
    const api = {
        validateToken: async (tokenId: string) => {
            const introspectUrl = `https://${baseInfranodeUrl}/innerApp/oauth2/introspect`;
            
            const response = await fetch(introspectUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    token: tokenId,
                    token_type_hint: "access_token"
                }),
                credentials: "include"
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Token validation failed: ${response.status} - ${errorText}`);
            }

            return await response.json() as UserDetails;
        },

        exchangeToken: async (params: Record<string, string>) => {
            const response = await fetch(`${baseUrl}/api/auth/token`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(params),
                credentials: "include"
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Token operation failed: ${response.status} - ${errorText}`);
            }

            const tokens = await response.json() as TokenResponse;

            if (!tokens.access_token && !tokens.status) {
                throw new Error("Received incomplete token data from server");
            }

            return tokens;
        }
    };

    const auth = {
        validateAndSetUser: async (accessToken: string) => {
            try {
                if (isLoggedIn && storage.getAccessToken() === accessToken) {
                    return;
                }
                
                const tokenId = extractJwtId(accessToken);
                if (!tokenId) {
                    const data = await api.validateToken(accessToken);
                    
                    if (data && data.active) {
                        setUserDetails(data);
                        setIsLoggedIn(true);
                        return;
                    }
                } else {
                    const data = await api.validateToken(tokenId);

                    if (data && data.active) {
                        setUserDetails(data);
                        setIsLoggedIn(true);
                        return;
                    }
                }
                
                await auth.refreshToken();
            } catch (err) {
                try {
                    await auth.refreshToken();
                } catch (refreshErr) {
                    storage.clearAuth();
                    setIsLoggedIn(false);
                    setUserDetails(null);
                    throw refreshErr;
                }
            }
        },

        exchangeCodeForToken: async (code: string) => {
            const codeVerifier = storage.get(STORAGE_KEYS.CODE_VERIFIER);

            if (!codeVerifier) {
                throw new Error("Missing code verifier");
            }

            try {
                const tokens = await api.exchangeToken({
                    client_id: clientId,
                    grant_type: "authorization_code",
                    code,
                    code_verifier: codeVerifier
                });
                
                storage.setAccessToken(tokens.access_token, tokens.expires_in || 3600);
                await auth.validateAndSetUser(tokens.access_token);
            } catch {}
        },

        refreshToken: async () => {
            try {
                const tokens = await api.exchangeToken({
                    client_id: clientId,
                    grant_type: "refresh_token"
                });
                
                if (!tokens || tokens.status === "auth_required") {
                    setIsLoggedIn(false);
                    setUserDetails(null);
                    return;
                }

                storage.setAccessToken(tokens.access_token, tokens.expires_in || 3600);
                await auth.validateAndSetUser(tokens.access_token);
            } catch (err) {
                storage.clearAuth();
                setIsLoggedIn(false);
                setUserDetails(null);
            }
        },

        initialize: async () => {
            try {
                const accessToken = storage.getAccessToken();
                const tokenExpiry = storage.getTokenExpiry();
                
                if (accessToken && tokenExpiry && tokenExpiry > Date.now()) {
                    await auth.validateAndSetUser(accessToken);
                } else {
                    const urlParams = new URLSearchParams(window.location.search);
                    const code = urlParams.get("code");

                    if (code) {
                        await auth.exchangeCodeForToken(code);
                        window.history.replaceState({}, document.title, window.location.pathname);
                    } else {
                        try {
                            await auth.refreshToken();
                        } catch (err) {
                            setIsLoggedIn(false);
                            setUserDetails(null);
                        }
                    }
                }
            } catch (err) {
                setIsLoggedIn(false);
                setUserDetails(null);
            }
        }
    };

    const login = useCallback(async () => {
        try {
            const codeVerifier = generateRandomString(43);
            const codeChallenge = await createCodeChallenge(codeVerifier);

            storage.set(STORAGE_KEYS.CODE_VERIFIER, codeVerifier);

            const authUrl = new URL(loginRedirectUrl);
            authUrl.searchParams.append("client_id", clientId);
            authUrl.searchParams.append("code_challenge", codeChallenge);
            authUrl.searchParams.append("code_challenge_method", "S256");
            authUrl.searchParams.append("redirect_uri", window.location.href);
            authUrl.searchParams.append("appName", document.title || "Solar Client App");

            window.location.href = authUrl.toString();
        } catch {}
    }, [loginRedirectUrl]);

    const logout = useCallback(async () => {
        try {
            await fetch(`${baseUrl}/api/auth/logout`, {
                method: 'POST',
                credentials: 'include'
            });
        } catch {} finally {
            storage.clearAuth();
            setIsLoggedIn(false);
            setUserDetails(null);
        }
    }, [baseUrl]);

    const isInitializing = useRef(false);
    
    useEffect(() => {
        if (isInitializing.current) return;
        isInitializing.current = true;
        setAuthLoading(true);

        auth.initialize().finally(() => {
            setAuthLoading(false);
            isInitializing.current = false;
        });
    }, []);

    return {
        isLoggedIn,
        userDetails,
        authLoading,
        login,
        logout,
        token: storage.getAccessToken()
    };
}