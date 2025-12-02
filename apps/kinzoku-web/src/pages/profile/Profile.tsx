import ProfileCard from "../../components/Card/ProfileCard";
import { useSelector } from "react-redux";

export default function ProfilePage() {
  const user = useSelector((state: RootState) => state.auth.user);

  if (!user) {
    return (
      <main className="min-h-[calc(100dvh-0px)] w-full bg-slate-950 text-slate-100 flex items-center justify-center">
        <p className="text-slate-400">No user logged in.</p>
      </main>
    );
  }

  return (
    <main className="min-h-[calc(100dvh-0px)] w-full bg-slate-950 text-slate-100">
      <section className="mx-auto max-w-5xl px-4 py-8 md:py-12">
        <div className="mb-6">
          <h1 className="text-2xl md:text-3xl font-semibold">Your Profile</h1>
          <p className="mt-1 text-slate-400">
            View and edit your personal information.
          </p>
        </div>

        <ProfileCard
          firstName={user.firstName}
          lastName={user.lastName}
          email={user.email}
          role = {user.role}
          avatarUrl={user.avatar} 
          onSave={async (data) => {
            console.log("Saved profile:", data);
            // dispatch(setUser({ id: user.id, name: `${data.firstName} ${data.lastName}`, email: data.email }))
          }}
        />
      </section>
    </main>
  );
}
