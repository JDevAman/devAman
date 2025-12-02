import { useCallback } from "react";
import { useAppDispatch } from "../store/hooks";
import { setUser } from "../store/slices/authSlice";
import { api, baseUrl } from "../api/api";
import { useAppNavigation } from "./useAppNavigation";
import { backendUrl } from "../api/api";

export function useOAuth() {
  const dispatch = useAppDispatch();
  const { goToDashboard } = useAppNavigation();

  const handleOAuth = useCallback(
    (provider: "google" | "github") => {
      const width = 500;
      const height = 600;
      const left = window.screen.width / 2 - width / 2;
      const top = window.screen.height / 2 - height / 2;

      const url = `${backendUrl}${baseUrl}/auth/${provider}`;
      const popup = window.open(
        url,
        "_blank",
        `width=${width},height=${height},top=${top},left=${left}`
      );

      const listener = (event: MessageEvent) => {
        if (event.origin !== backendUrl) return;

        if (event.data.success) {
          (async () => {
            try {
              const res = await api.get(`${backendUrl}${baseUrl}/user/me`);
              console.log(res);
              dispatch(setUser(res.data.user));
              goToDashboard();
            } catch (err) {
              console.error("OAuth login failed", err);
            }
          })();
          window.removeEventListener("message", listener);
        }
      };

      window.addEventListener("message", listener);
    },
    [backendUrl, dispatch, goToDashboard]
  );

  return { handleOAuth };
}
