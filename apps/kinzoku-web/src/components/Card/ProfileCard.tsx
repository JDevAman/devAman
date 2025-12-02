import React, { useState, useRef, useMemo } from "react";
import { Avatar, AvatarImage, AvatarFallback } from "../ui/avatar";
import { Button } from "../Button/Button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "./Card";
import { Input } from "../ui/input";
import { cn } from "../../utils/utils";
import { userSignInSchema } from "../../../shared/validators";

export type ProfileData = {
  firstName: string;
  lastName: string;
  email: string;
  avatarUrl?: string;
};

export interface ProfileCardProps {
  firstName?: string;
  lastName?: string;
  email?: string;
  avatarUrl?: string;
  role?: string;
  onSave?: (data: ProfileData) => Promise<void> | void;
  className?: string;
}

function getInitials(firstName?: string, lastName?: string) {
  const fi = firstName?.trim()?.[0] ?? "";
  const li = lastName?.trim()?.[0] ?? "";
  return (fi + li).toUpperCase() || "U";
}

function isValidEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

const ProfileCard: React.FC<ProfileCardProps> = ({
  firstName = "Alex",
  lastName = "Chen",
  email = "alex@example.com",
  role = "USER",
  avatarUrl,
  onSave,
  className,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [editMode, setEditMode] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [localFirst, setLocalFirst] = useState(firstName);
  const [localLast, setLocalLast] = useState(lastName);
  const [localEmail, setLocalEmail] = useState(email);
  const [localRole, setLocalRole] = useState(role);
  const [localAvatarUrl, setLocalAvatarUrl] = useState(avatarUrl);

  const initials = useMemo(
    () => getInitials(localFirst, localLast),
    [localFirst, localLast]
  );

  const handlePickAvatar = () => fileInputRef.current?.click();

  const handleAvatarChange: React.ChangeEventHandler<HTMLInputElement> = (
    e
  ) => {
    const file = e.target.files?.[0];
    if (file) setLocalAvatarUrl(URL.createObjectURL(file));
  };

  const resetEdits = () => {
    setLocalFirst(firstName);
    setLocalLast(lastName);
    setLocalEmail(email);
    setLocalRole(role);
    setLocalAvatarUrl(avatarUrl);
    setError(null);
  };

  const handleCancel = () => {
    resetEdits();
    setEditMode(false);
  };

  const handleSave = async () => {
    setError(null);
    if (!localFirst.trim() || !localLast.trim()) {
      setError("First and last name are required.");
      return;
    }
    if (!isValidEmail(localEmail)) {
      setError("Please enter a valid email address.");
      return;
    }

    setSaving(true);
    try {
      const payload: ProfileData = {
        firstName: localFirst.trim(),
        lastName: localLast.trim(),
        email: localEmail.trim(),
        avatarUrl: localAvatarUrl,
      };
      if (onSave) await onSave(payload);
      else await new Promise((r) => setTimeout(r, 800));
      setEditMode(false);
    } catch {
      setError("Failed to save changes. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card
      className={cn(
        "max-w-2xl w-full bg-slate-900/60 border-slate-800",
        className
      )}
    >
      <CardHeader>
        <CardTitle className="text-white">Profile</CardTitle>
        <CardDescription className="text-slate-400">
          Manage your personal information and profile picture.
        </CardDescription>
      </CardHeader>

      <CardContent className="grid gap-6">
        {/* Avatar */}
        <div className="flex items-center gap-4">
          <Avatar className="h-16 w-16 ring-1 ring-slate-700">
            {localAvatarUrl ? (
              <AvatarImage src={localAvatarUrl} alt="Profile avatar" />
            ) : (
              <AvatarFallback>{initials}</AvatarFallback>
            )}
          </Avatar>
          <div className="flex-1">
            <p className="text-sm text-slate-300">
              Use a square image for best results.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={handleAvatarChange}
              />
              <Button
                type="button"
                variant="glow"
                size="sm"
                onClick={handlePickAvatar}
              >
                Change picture
              </Button>
              {localAvatarUrl && editMode && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setLocalAvatarUrl(undefined)}
                >
                  Remove
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* Name Fields */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Input
            value={localFirst}
            onChange={(e) => setLocalFirst(e.target.value)}
            disabled={!editMode || saving}
            placeholder="First name"
          />
          <Input
            value={localLast}
            onChange={(e) => setLocalLast(e.target.value)}
            disabled={!editMode || saving}
            placeholder="Last name"
          />
        </div>

        {/* Email */}
        <Input
          type="email"
          value={localEmail}
          onChange={(e) => setLocalEmail(e.target.value)}
          disabled={!editMode || saving}
          placeholder="you@example.com"
        />
        <Input
          type="role"
          value={localEmail}
          onChange={(e) => setLocalRole(e.target.value)}
          disabled={true}
          placeholder="User"
        />

        {error && <p className="text-sm text-red-400">{error}</p>}
      </CardContent>

      <CardFooter className="flex items-center justify-between gap-3">
        {!editMode ? (
          <>
            <div className="text-sm text-slate-400">
              Keep your details up to date for better security.
            </div>
            <Button
              type="button"
              variant="glow"
              onClick={() => setEditMode(true)}
            >
              Edit Profile
            </Button>
          </>
        ) : (
          <div className="ml-auto flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={handleCancel}
              disabled={saving}
            >
              Cancel
            </Button>
            <Button
              type="button"
              onClick={handleSave}
              disabled={saving}
              className="bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/20"
            >
              {saving ? "Saving..." : "Save changes"}
            </Button>
          </div>
        )}
      </CardFooter>
    </Card>
  );
};

export default ProfileCard;
