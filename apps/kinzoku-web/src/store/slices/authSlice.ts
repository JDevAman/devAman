import { createSlice, PayloadAction } from "@reduxjs/toolkit";

interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: string;
}

interface AuthState {
  user: User | null;
  signupEmail: string | null;
  loading: boolean; // NEW: track if user is being fetched
}

const initialState: AuthState = {
  user: null,
  signupEmail: null,
  loading: false, // initially true, we’ll fetch user on app init
};

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    setUser: (state, action: PayloadAction<User | null>) => {
      state.user = action.payload;
      state.loading = false; // done fetching
    },
    logout: (state) => {
      state.user = null;
      state.loading = false;
    },
    setSignupEmail: (state, action: PayloadAction<string>) => {
      state.signupEmail = action.payload;
    },
    startLoading: (state) => {
      state.loading = true; // optional: use if manually triggering fetch
    },
  },
});

export const { setUser, logout, setSignupEmail, startLoading } =
  authSlice.actions;
export default authSlice.reducer;
