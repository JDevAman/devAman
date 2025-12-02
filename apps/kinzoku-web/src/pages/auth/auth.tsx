import { useState, useEffect, useCallback, useMemo } from "react";
import { Button } from "../../components/Button/Button";
import { InputField } from "../../components/Form/InputField";
import { AuthCard } from "../../components/Card/AuthCard";
import { Github } from "lucide-react";
import { useLocation } from "react-router-dom";
import { useAppNavigation } from "../../utils/useAppNavigation";
import { useAppDispatch, useAppSelector } from "../../store/hooks";
import { setUser } from "../../store/slices/authSlice";
import { TabButton } from "../../components/Button/TabButton";
import { api } from "../../api/api";
import { useOAuth } from "../../utils/useOAuth";
import { GoogleIcon } from "../../components/icons/GoogleIcon";
import { regex } from "../../../shared/validators";

type Tab = "signin" | "signup";

export function AuthPage() {
  const { goToDashboard, goToSignIn, goToSignUp, goToForgotPassword } =
    useAppNavigation();
  const { pathname } = useLocation();
  const dispatch = useAppDispatch();
  const { handleOAuth } = useOAuth();
  const signupEmail = useAppSelector((state) => state.auth.signupEmail);

  // ---------------- State ----------------
  const [activeTab, setActiveTab] = useState<Tab>("signin");
  const [formData, setFormData] = useState({
    email: signupEmail || "",
    password: "",
    confirmPassword: "",
    firstName: "",
    lastName: "",
  });
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [fieldValid, setFieldValid] = useState({
    email: false,
    password: false,
    confirmPassword: false,
    firstName: false,
    lastName: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // ---------------- Active tab from URL ----------------
  useEffect(() => {
    setActiveTab(pathname.includes("signup") ? "signup" : "signin");
  }, [pathname]);

  // ---------------- Field change handlers ----------------
  const handleFieldChange =
    (field: keyof typeof formData) =>
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value.trim();
      setFormData((prev) => ({ ...prev, [field]: value }));

      // Validation logic
      switch (field) {
        case "email":
          if (!value) {
            setFieldErrors((prev) => ({ ...prev, email: "" }));
            setFieldValid((prev) => ({ ...prev, email: false }));
          } else if (regex.email.test(value)) {
            setFieldErrors((prev) => ({ ...prev, email: "" }));
            setFieldValid((prev) => ({ ...prev, email: true }));
          } else {
            setFieldErrors((prev) => ({
              ...prev,
              email: "Invalid email address",
            }));
            setFieldValid((prev) => ({ ...prev, email: false }));
          }
          break;

        case "password":
          if (!value) {
            setFieldErrors((prev) => ({ ...prev, password: "" }));
            setFieldValid((prev) => ({ ...prev, password: false }));
          } else if (regex.password.test(value)) {
            setFieldErrors((prev) => ({ ...prev, password: "" }));
            setFieldValid((prev) => ({ ...prev, password: true }));
          } else {
            setFieldErrors((prev) => ({
              ...prev,
              password: "Password must be 6+ chars, include letters & numbers",
            }));
            setFieldValid((prev) => ({ ...prev, password: false }));
          }

          // Check confirm password match if in signup
          if (activeTab === "signup") {
            if (
              formData.confirmPassword &&
              formData.confirmPassword !== value
            ) {
              setFieldErrors((prev) => ({
                ...prev,
                confirmPassword: "Passwords do not match",
              }));
              setFieldValid((prev) => ({ ...prev, confirmPassword: false }));
            } else if (formData.confirmPassword === value) {
              setFieldErrors((prev) => ({ ...prev, confirmPassword: "" }));
              setFieldValid((prev) => ({ ...prev, confirmPassword: true }));
            }
          }
          break;

        case "confirmPassword":
          if (!value) {
            setFieldErrors((prev) => ({ ...prev, confirmPassword: "" }));
            setFieldValid((prev) => ({ ...prev, confirmPassword: false }));
          } else if (value === formData.password) {
            setFieldErrors((prev) => ({ ...prev, confirmPassword: "" }));
            setFieldValid((prev) => ({ ...prev, confirmPassword: true }));
          } else {
            setFieldErrors((prev) => ({
              ...prev,
              confirmPassword: "Passwords do not match",
            }));
            setFieldValid((prev) => ({ ...prev, confirmPassword: false }));
          }
          break;

        case "firstName":
          if (value.length >= 2 && value.length <= 20) {
            setFieldErrors((prev) => ({ ...prev, firstName: "" }));
            setFieldValid((prev) => ({ ...prev, firstName: true }));
          } else {
            setFieldErrors((prev) => ({
              ...prev,
              firstName: "First name required with 2 - 20 chars",
            }));
            setFieldValid((prev) => ({ ...prev, firstName: false }));
          }
          break;

        case "lastName":
          if (value.length >= 2 && value.length <= 20) {
            setFieldErrors((prev) => ({ ...prev, lastName: "" }));
            setFieldValid((prev) => ({ ...prev, lastName: true }));
          } else {
            setFieldErrors((prev) => ({
              ...prev,
              lastName: "Last name required with 2 - 20 chars",
            }));
            setFieldValid((prev) => ({ ...prev, lastName: false }));
          }
          break;
      }
    };

  // ---------------- Form validity ----------------
  const isFormValid =
    activeTab === "signin"
      ? fieldValid.email && fieldValid.password
      : fieldValid.email &&
        fieldValid.password &&
        fieldValid.confirmPassword &&
        fieldValid.firstName &&
        fieldValid.lastName;

  // ---------------- Tab & Submit handlers ----------------
  const handleTabClick = useCallback(
    (tab: Tab) => {
      if (tab === activeTab) return;
      tab === "signin" ? goToSignIn() : goToSignUp();
      setActiveTab(tab);
    },
    [activeTab, goToSignIn, goToSignUp]
  );

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!isFormValid) return;

      setError("");
      setLoading(true);

      try {
        const res = await api.post(`user/${activeTab}`, {
          email: formData.email,
          password: formData.password,
          ...(activeTab === "signup" && {
            firstName: formData.firstName,
            lastName: formData.lastName,
          }),
        });
        dispatch(setUser(res.data.user));
        goToDashboard();
      } catch (err: any) {
        setError(err.response?.data?.message || "Something went wrong");
      } finally {
        setLoading(false);
      }
    },
    [activeTab, formData, dispatch, goToDashboard, isFormValid]
  );

  // ---------------- Card titles ----------------
  const cardTitle = useMemo(
    () => (activeTab === "signin" ? "Welcome Back" : "Create Account"),
    [activeTab]
  );
  const cardSubtitle = useMemo(
    () =>
      activeTab === "signin"
        ? "Sign in to your account"
        : "Join KinzokuPay today",
    [activeTab]
  );

  return (
    <div className="min-h-screen bg-black flex items-start justify-center p-8">
      <div className="w-full max-w-md">
        <div className="flex bg-slate-900/50 rounded-lg mb-8">
          <TabButton
            tab="signin"
            activeTab={activeTab}
            onClick={handleTabClick}
            label="Sign In"
          />
          <TabButton
            tab="signup"
            activeTab={activeTab}
            onClick={handleTabClick}
            label="Sign Up"
          />
        </div>

        <AuthCard title={cardTitle} subtitle={cardSubtitle}>
          <form onSubmit={handleSubmit} className="space-y-6">
            {activeTab === "signup" && (
              <div className="grid grid-cols-2 gap-4">
                <InputField
                  type="text"
                  label="First Name"
                  placeholder="John"
                  value={formData.firstName}
                  onChange={handleFieldChange("firstName")}
                  error={fieldErrors.firstName}
                />
                <InputField
                  type="text"
                  label="Last Name"
                  placeholder="Doe"
                  value={formData.lastName}
                  onChange={handleFieldChange("lastName")}
                  error={fieldErrors.lastName}
                />
              </div>
            )}

            <InputField
              type="email"
              label="Email"
              placeholder="Enter your email"
              value={formData.email}
              onChange={handleFieldChange("email")}
              error={fieldErrors.email}
            />
            <InputField
              type="password"
              label="Password"
              placeholder="Enter your password"
              value={formData.password}
              onChange={handleFieldChange("password")}
              error={fieldErrors.password}
            />
            {activeTab === "signup" && (
              <InputField
                type="password"
                label="Confirm Password"
                placeholder="Confirm your password"
                value={formData.confirmPassword}
                onChange={handleFieldChange("confirmPassword")}
                error={fieldErrors.confirmPassword}
              />
            )}

            {error && <p className="text-red-500 text-sm">{error}</p>}

            <Button
              type="submit"
              variant={isFormValid ? "glow" : "default"}
              className="w-full"
              disabled={!isFormValid || loading}
            >
              {loading
                ? "Please wait..."
                : activeTab === "signin"
                ? "Sign In"
                : "Create Account"}
            </Button>

            {/* OAuth */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-slate-700" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-slate-900 text-slate-400">
                  Or continue with
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Button
                type="button"
                variant="outline"
                className="w-full bg-transparent"
                onClick={() => handleOAuth("google")}
              >
                <GoogleIcon className="w-5 h-5 mr-2" />
                Google
              </Button>
              <Button
                type="button"
                variant="outline"
                className="w-full bg-transparent"
                onClick={() => handleOAuth("github")}
              >
                <Github className="w-5 h-5 mr-2" /> GitHub
              </Button>
            </div>

            <div className="text-center">
              <button
                type="button"
                onClick={goToForgotPassword}
                className="text-slate-400 hover:text-white text-sm transition-colors"
              >
                Forgot Password ?
              </button>
            </div>
          </form>
        </AuthCard>
      </div>
    </div>
  );
}
