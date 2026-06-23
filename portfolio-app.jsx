/* global React, ReactDOM, PORTFOLIO, NAV, Nav, Hero, About, Skills, Projects, ProjectModal, Creds, Contact,
   useTweaks, TweaksPanel, TweakSection, TweakColor, TweakRadio, TweakToggle */
const { useState, useEffect, useRef } = React;

const ACCENTS = {
  cyan:   { a: "oklch(0.82 0.13 200)", dim: "oklch(0.82 0.13 200 / 0.14)" },
  green:  { a: "oklch(0.84 0.17 150)", dim: "oklch(0.84 0.17 150 / 0.14)" },
  violet: { a: "oklch(0.74 0.15 290)", dim: "oklch(0.74 0.15 290 / 0.14)" },
  amber:  { a: "oklch(0.82 0.13 75)",  dim: "oklch(0.82 0.13 75 / 0.14)" },
};

const FONTS = {
  "Space Grotesk": "'Space Grotesk', system-ui, sans-serif",
  "JetBrains Mono": "'JetBrains Mono', ui-monospace, monospace",
  "IBM Plex Sans": "'IBM Plex Sans', system-ui, sans-serif",
};

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "cyan",
  "displayFont": "Space Grotesk",
  "scanlines": true,
  "density": "regular"
}/*EDITMODE-END*/;

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [active, setActive] = useState("about");
  const [openProject, setOpenProject] = useState(null);
  const P = PORTFOLIO;

  // apply accent + font + density to :root
  useEffect(() => {
    const r = document.documentElement;
    const ac = ACCENTS[t.accent] || ACCENTS.cyan;
    r.style.setProperty("--accent", ac.a);
    r.style.setProperty("--accent-dim", ac.dim);
    r.style.setProperty("--display-font", FONTS[t.displayFont] || FONTS["Space Grotesk"]);
    const pad = t.density === "compact" ? "96px" : t.density === "comfy" ? "180px" : "136px";
    r.style.setProperty("--section-gap", pad);
    r.setAttribute("data-scanlines", t.scanlines ? "on" : "off");
  }, [t.accent, t.displayFont, t.scanlines, t.density]);

  // scroll-spy
  useEffect(() => {
    const ids = ["about", "skills", "work", "creds", "contact"];
    const obs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) setActive(e.target.id);
        });
      },
      { rootMargin: "-45% 0px -50% 0px", threshold: 0 }
    );
    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) obs.observe(el);
    });
    return () => obs.disconnect();
  }, []);

  function jump(id) {
    const el = id === "top" ? document.body : document.getElementById(id);
    if (!el) return;
    const top = id === "top" ? 0 : el.getBoundingClientRect().top + window.scrollY - 72;
    window.scrollTo({ top, behavior: "smooth" });
  }

  return (
    <div className="app">
      <div className="grain" aria-hidden="true" />
      <Nav active={active} onJump={jump} identity={P.identity} />
      <main>
        <Hero identity={P.identity} onJump={jump} />
        <About identity={P.identity} stats={P.stats} />
        <Skills skills={P.skills} />
        <Projects projects={P.projects} onOpen={setOpenProject} />
        <Creds certs={P.certs} experience={P.experience} />
        <Contact contact={P.contact} identity={P.identity} />
      </main>

      {openProject && <ProjectModal project={openProject} onClose={() => setOpenProject(null)} />}

      <TweaksPanel>
        <TweakSection label="Accent" />
        <TweakColor
          label="Accent color"
          value={ACCENTS[t.accent].a}
          options={Object.values(ACCENTS).map((x) => x.a)}
          onChange={(v) => {
            const key = Object.keys(ACCENTS).find((k) => ACCENTS[k].a === v) || "cyan";
            setTweak("accent", key);
          }}
        />
        <TweakSection label="Type" />
        <TweakRadio
          label="Display font"
          value={t.displayFont}
          options={["Space Grotesk", "JetBrains Mono", "IBM Plex Sans"]}
          onChange={(v) => setTweak("displayFont", v)}
        />
        <TweakSection label="Layout" />
        <TweakRadio
          label="Density"
          value={t.density}
          options={["compact", "regular", "comfy"]}
          onChange={(v) => setTweak("density", v)}
        />
        <TweakToggle
          label="CRT scanlines"
          value={t.scanlines}
          onChange={(v) => setTweak("scanlines", v)}
        />
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
