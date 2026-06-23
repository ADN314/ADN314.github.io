/* global React */
const { useState, useEffect, useRef } = React;

/* ----------------------------------------------------------------- *
 * Small primitives
 * ----------------------------------------------------------------- */

function Section({ id, eyebrow, title, children }) {
  return (
    <section id={id} className="section" data-screen-label={id}>
      <div className="section-head">
        <span className="eyebrow">
          <span className="eyebrow-mark">{"//"}</span> {eyebrow}
        </span>
        <h2 className="section-title">{title}</h2>
      </div>
      {children}
    </section>
  );
}

/* A striped placeholder for imagery the user should drop in. */
function Placeholder({ label, ratio = "16 / 10" }) {
  return (
    <div className="placeholder" style={{ aspectRatio: ratio }}>
      <span className="placeholder-label">{label}</span>
    </div>
  );
}

/* ----------------------------------------------------------------- *
 * Nav — sticky, scroll-spy
 * ----------------------------------------------------------------- */

const NAV = [
  { id: "about", label: "about" },
  { id: "skills", label: "skills" },
  { id: "work", label: "work" },
  { id: "creds", label: "creds" },
  { id: "contact", label: "contact" },
];

function Nav({ active, onJump, identity }) {
  return (
    <header className="nav">
      <button className="nav-brand" onClick={() => onJump("top")}>
        <span className="brand-dot" />
        <span className="brand-name">{identity.name}</span>
        <span className="brand-role">{identity.role}</span>
      </button>
      <nav className="nav-links">
        {NAV.map((n) => (
          <button
            key={n.id}
            className={"nav-link" + (active === n.id ? " is-active" : "")}
            onClick={() => onJump(n.id)}
          >
            <span className="nav-num">{String(NAV.indexOf(n) + 1).padStart(2, "0")}</span>
            {n.label}
          </button>
        ))}
      </nav>
      <div className="nav-status">
        <span className="status-pulse" />
        available
      </div>
    </header>
  );
}

/* ----------------------------------------------------------------- *
 * Hero — typing terminal
 * ----------------------------------------------------------------- */

function useTypewriter(lines, deps) {
  const [out, setOut] = useState(() => lines.map((l) => ({ ...l, text: "" })));
  const [active, setActive] = useState(0);
  const [done, setDone] = useState(false);
  useEffect(() => {
    let cancelled = false;
    let li = 0;
    let ci = 0;
    const rendered = lines.map((l) => ({ ...l, text: "" }));
    setOut(rendered.map((r) => ({ ...r })));
    setActive(0);
    setDone(false);

    function tick() {
      if (cancelled) return;
      if (li >= lines.length) {
        setDone(true);
        return;
      }
      const target = lines[li];
      setActive(li);
      if (ci <= target.text.length) {
        rendered[li].text = target.text.slice(0, ci);
        ci += 1;
        setOut(rendered.map((r) => ({ ...r })));
        setTimeout(tick, target.text[ci - 1] === " " ? 16 : 22);
      } else {
        li += 1;
        ci = 0;
        setTimeout(tick, 260);
      }
    }
    const start = setTimeout(tick, 400);
    return () => {
      cancelled = true;
      clearTimeout(start);
    };
    // eslint-disable-next-line
  }, deps);
  return { out, active, done };
}

function Hero({ identity, onJump }) {
  const lines = [
    { kind: "cmd", text: "whoami" },
    { kind: "out", text: identity.name + "  —  " + identity.role },
    { kind: "cmd", text: "cat ./mission.txt" },
    { kind: "out", text: identity.tagline },
    { kind: "cmd", text: "./status --now" },
    { kind: "ok", text: identity.availability + "  ·  " + identity.location },
  ];
  const { out, active, done } = useTypewriter(lines, []);

  return (
    <div className="hero" id="top">
      <div className="hero-grid">
        <div className="hero-copy">
          <p className="hero-kicker">{identity.role}</p>
          <h1 className="hero-title">
            {identity.name}
            <span className="hero-cursor-blink">_</span>
          </h1>
          <p className="hero-blurb">{identity.blurb}</p>
          <div className="hero-cta">
            <button className="btn btn-primary" onClick={() => onJump("work")}>
              View work
            </button>
            <button className="btn btn-ghost" onClick={() => onJump("contact")}>
              Get in touch
            </button>
          </div>
        </div>

        <div className="terminal" role="img" aria-label="terminal session introducing the portfolio">
          <div className="terminal-bar">
            <span className="tdot" />
            <span className="tdot" />
            <span className="tdot" />
            <span className="terminal-title">{identity.handle}@vale — zsh</span>
          </div>
          <div className="terminal-body">
            {out.map((l, i) => (
              (i < active || l.text.length > 0 || (done)) && (
                <div className={"tline t-" + l.kind} key={i}>
                  {l.kind === "cmd" && <span className="tprompt">$</span>}
                  {l.kind === "ok" && <span className="tok">✓</span>}
                  <span className="ttext">{l.text}</span>
                  {!done && i === active && <span className="tcursor">▋</span>}
                </div>
              )
            ))}
            {done && (
              <div className="tline t-cmd">
                <span className="tprompt">$</span>
                <span className="tcursor">▋</span>
              </div>
            )}
          </div>
        </div>
      </div>
      <button className="scroll-hint" onClick={() => onJump("about")}>
        scroll <span>↓</span>
      </button>
    </div>
  );
}

/* ----------------------------------------------------------------- *
 * About + stats
 * ----------------------------------------------------------------- */

function About({ identity, stats }) {
  return (
    <Section id="about" eyebrow="about" title="Adversarial by trade.">
      <div className="about-grid">
        <div className="about-text">
          <p>{identity.blurb}</p>
          <p>
            I work the full spectrum — from a focused web app test to a multi-week
            full-scope red team — and I care most about the part everyone skips:
            making findings legible enough that they actually get fixed.
          </p>
        </div>
        <div className="stats">
          {stats.map((s) => (
            <div className="stat" key={s.label}>
              <span className="stat-value">{s.value}</span>
              <span className="stat-label">{s.label}</span>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}

/* ----------------------------------------------------------------- *
 * Skills
 * ----------------------------------------------------------------- */

function Skills({ skills }) {
  return (
    <Section id="skills" eyebrow="capabilities" title="What I bring.">
      <div className="skills-grid">
        {skills.map((s) => (
          <div className="skill-card" key={s.group}>
            <h3 className="skill-group">{s.group}</h3>
            <ul className="skill-tags">
              {s.items.map((it) => (
                <li className="tag" key={it}>{it}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}

/* ----------------------------------------------------------------- *
 * Work / projects
 * ----------------------------------------------------------------- */

function Projects({ projects, onOpen }) {
  return (
    <Section id="work" eyebrow="selected work" title="Case studies.">
      <div className="projects">
        {projects.map((p, i) => (
          <button className="project" key={p.id} onClick={() => onOpen(p)}>
            <div className="project-media">
              <Placeholder label="engagement visual" />
              <span className="project-kind">{p.kind}</span>
            </div>
            <div className="project-info">
              <span className="project-index">{String(i + 1).padStart(2, "0")} / {p.year}</span>
              <h3 className="project-name">{p.name}</h3>
              <p className="project-summary">{p.summary}</p>
              <span className="project-open">open case study →</span>
            </div>
          </button>
        ))}
      </div>
    </Section>
  );
}

function ProjectModal({ project, onClose }) {
  useEffect(() => {
    function onKey(e) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, []);
  if (!project) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>
        <span className="modal-kind">{project.kind} · {project.year}</span>
        <h2 className="modal-title">{project.name}</h2>
        <p className="modal-summary">{project.summary}</p>
        <Placeholder label="engagement visual / redacted screenshot" ratio="16 / 7" />
        <div className="modal-meta">
          <div><span className="meta-k">Role</span><span className="meta-v">{project.role}</span></div>
          <div><span className="meta-k">Duration</span><span className="meta-v">{project.duration}</span></div>
          <div><span className="meta-k">Stack</span><span className="meta-v">{project.stack.join(" · ")}</span></div>
        </div>
        <h3 className="modal-subhead">Impact</h3>
        <ul className="modal-impact">
          {project.impact.map((it, i) => (
            <li key={i}><span className="impact-mark">▸</span>{it}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- *
 * Creds — certs + experience
 * ----------------------------------------------------------------- */

function Creds({ certs, experience }) {
  return (
    <Section id="creds" eyebrow="credentials" title="Proof of work.">
      <div className="creds-grid">
        <div className="certs">
          <h3 className="creds-sub">Certifications</h3>
          <div className="cert-list">
            {certs.map((c) => (
              <div className="cert" key={c.abbr} title={c.name}>
                <span className="cert-abbr">{c.abbr}</span>
                <span className="cert-name">{c.name}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="timeline">
          <h3 className="creds-sub">Experience</h3>
          {experience.map((e) => (
            <div className="tl-item" key={e.role}>
              <span className="tl-period">{e.period}</span>
              <div className="tl-body">
                <h4 className="tl-role">{e.role} <span className="tl-org">· {e.org}</span></h4>
                <p className="tl-note">{e.note}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}

/* ----------------------------------------------------------------- *
 * Contact
 * ----------------------------------------------------------------- */

function Contact({ contact, identity }) {
  const [copied, setCopied] = useState(false);
  function copyEmail() {
    navigator.clipboard?.writeText(contact.email).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1600);
      },
      () => {}
    );
  }
  return (
    <Section id="contact" eyebrow="contact" title="Let's talk scope.">
      <div className="contact-grid">
        <div className="contact-main">
          <p className="contact-lead">
            Engagements, research collaboration, or a second opinion on your threat model —
            reach out and tell me what you're protecting.
          </p>
          <div className="contact-email">
            <button className="email-btn" onClick={copyEmail}>
              <span className="tprompt">$</span> mail {contact.email}
              <span className="copy-state">{copied ? "copied ✓" : "click to copy"}</span>
            </button>
          </div>
          <div className="pgp">
            <span className="pgp-k">PGP</span>
            <span className="pgp-v">{contact.pgp}</span>
          </div>
        </div>
        <div className="contact-links">
          {contact.links.map((l) => (
            <div className="clink" key={l.label}>
              <span className="clink-label">{l.label}</span>
              <span className="clink-handle">{l.handle}</span>
            </div>
          ))}
        </div>
      </div>
      <footer className="footer">
        <span>© {new Date().getFullYear()} {identity.name}</span>
        <span className="footer-mono">built in the terminal · {identity.location}</span>
      </footer>
    </Section>
  );
}

Object.assign(window, {
  Section, Placeholder, Nav, Hero, About, Skills,
  Projects, ProjectModal, Creds, Contact, NAV,
});
