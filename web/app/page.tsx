import { Nav } from "@/components/nav";
import { Hero } from "@/components/hero";
import { Features } from "@/components/features";
import { Demo } from "@/components/demo";
import { Architecture } from "@/components/architecture";
import { Footer } from "@/components/footer";

export default function Home() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Features />
        <Demo />
        <Architecture />
      </main>
      <Footer />
    </>
  );
}
