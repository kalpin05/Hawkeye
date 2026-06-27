export default function Landing({ onGetStarted }) {
  const styles = {
    page: {
      minHeight:  "100vh",
      background: "#0D0D0D",
      color:      "#E0E0E0",
      fontFamily: "'Segoe UI', Arial, sans-serif",
    },
    nav: {
      background:    "#0D1B2A",
      borderBottom:  "2px solid #00FFFF",
      padding:       "0 3rem",
      height:        "56px",
      display:       "flex",
      alignItems:    "center",
      justifyContent:"space-between",
    },
    logo: {
      color:         "#00FFFF",
      fontWeight:    "bold",
      fontSize:      "1.2rem",
      letterSpacing: "3px",
    },
    navBtn: {
      background:   "#00FFFF",
      border:       "none",
      color:        "#000",
      padding:      "8px 20px",
      borderRadius: "6px",
      cursor:       "pointer",
      fontWeight:   "bold",
      fontSize:     "0.9rem",
    },
    hero: {
      textAlign: "center",
      padding:   "100px 20px 80px",
    },
    heroLogo: {
      fontSize:      "3.5rem",
      fontWeight:    "bold",
      color:         "#00FFFF",
      letterSpacing: "6px",
      marginBottom:  "1rem",
    },
    heroSub: {
      fontSize:     "1.1rem",
      color:        "#888",
      marginBottom: "0.5rem",
      letterSpacing:"2px",
    },
    heroTagline: {
      fontSize:   "1.4rem",
      color:      "#CCC",
      maxWidth:   "650px",
      margin:     "0 auto 2.5rem",
      lineHeight: "1.7",
    },
    ctaBtn: {
      background:    "#00FFFF",
      border:        "none",
      color:         "#000",
      padding:       "16px 48px",
      fontSize:      "1.1rem",
      fontWeight:    "bold",
      borderRadius:  "8px",
      cursor:        "pointer",
      letterSpacing: "1px",
    },
    ctaNote: {
      color:     "#555",
      fontSize:  "0.85rem",
      marginTop: "12px",
    },
    section: {
      padding:    "70px 2rem",
      maxWidth:   "1100px",
      margin:     "0 auto",
    },
    sectionDark: {
      background: "#111",
      padding:    "70px 2rem",
    },
    sectionTitle: {
      textAlign:     "center",
      fontSize:      "0.85rem",
      color:         "#00FFFF",
      letterSpacing: "3px",
      marginBottom:  "3rem",
    },
    grid3: {
      display:             "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
      gap:                 "1.5rem",
      maxWidth:            "1000px",
      margin:              "0 auto",
    },
    featureCard: {
      background:   "#1A1A1A",
      border:       "1px solid #222",
      borderRadius: "12px",
      padding:      "2rem",
      textAlign:    "center",
    },
    featureIcon: {
      fontSize:     "2.5rem",
      marginBottom: "1rem",
    },
    featureTitle: {
      color:        "#00FFFF",
      marginBottom: "0.75rem",
      fontSize:     "1rem",
    },
    featureText: {
      color:      "#888",
      fontSize:   "0.9rem",
      lineHeight: "1.6",
    },
    statsRow: {
      display:        "flex",
      justifyContent: "center",
      gap:            "4rem",
      flexWrap:       "wrap",
      padding:        "60px 2rem",
    },
    stat: {
      textAlign: "center",
    },
    statNum: {
      fontSize:   "3rem",
      fontWeight: "bold",
      color:      "#00FFFF",
    },
    statLabel: {
      color:         "#888",
      fontSize:      "0.85rem",
      letterSpacing: "1px",
      marginTop:     "4px",
    },
    plansGrid: {
      display:        "flex",
      gap:            "1.5rem",
      justifyContent: "center",
      flexWrap:       "wrap",
      maxWidth:       "1000px",
      margin:         "0 auto",
    },
    plan: {
      background:   "#1A1A1A",
      border:       "1px solid #222",
      borderRadius: "12px",
      padding:      "2rem",
      minWidth:     "210px",
      flex:         "1",
      maxWidth:     "240px",
    },
    planPopular: {
      background:   "#0D1B2A",
      border:       "2px solid #00FFFF",
      borderRadius: "12px",
      padding:      "2rem",
      minWidth:     "210px",
      flex:         "1",
      maxWidth:     "240px",
    },
    planName: {
      color:        "#888",
      fontSize:     "0.85rem",
      letterSpacing:"2px",
      marginBottom: "8px",
    },
    planPrice: {
      fontSize:     "2.2rem",
      fontWeight:   "bold",
      color:        "#00FFFF",
      marginBottom: "4px",
    },
    planPriceSub: {
      fontSize: "1rem",
      color:    "#555",
    },
    planFeature: {
      color:         "#CCC",
      fontSize:      "0.85rem",
      padding:       "7px 0",
      borderBottom:  "1px solid #222",
      display:       "flex",
      alignItems:    "center",
      gap:           "8px",
    },
    planBtn: {
      width:        "100%",
      padding:      "12px",
      background:   "#00FFFF",
      border:       "none",
      borderRadius: "8px",
      cursor:       "pointer",
      fontWeight:   "bold",
      fontSize:     "0.9rem",
      marginTop:    "1.5rem",
      color:        "#000",
    },
    planBtnOutline: {
      width:        "100%",
      padding:      "12px",
      background:   "transparent",
      border:       "1px solid #00FFFF",
      borderRadius: "8px",
      cursor:       "pointer",
      fontWeight:   "bold",
      fontSize:     "0.9rem",
      marginTop:    "1.5rem",
      color:        "#00FFFF",
    },
    howStep: {
      display:    "flex",
      gap:        "1.5rem",
      alignItems: "flex-start",
      marginBottom:"2rem",
      maxWidth:   "600px",
      margin:     "0 auto 2rem",
    },
    stepNum: {
      minWidth:     "44px",
      height:       "44px",
      background:   "#00FFFF",
      color:        "#000",
      borderRadius: "50%",
      display:      "flex",
      alignItems:   "center",
      justifyContent:"center",
      fontWeight:   "bold",
      fontSize:     "1.1rem",
      flexShrink:   0,
    },
    stepText: {
      paddingTop: "8px",
    },
    stepTitle: {
      color:        "#E0E0E0",
      fontWeight:   "500",
      marginBottom: "4px",
    },
    stepDesc: {
      color:    "#888",
      fontSize: "0.9rem",
    },
    footer: {
      textAlign:    "center",
      padding:      "2.5rem",
      color:        "#444",
      fontSize:     "0.8rem",
      borderTop:    "1px solid #1A1A1A",
      marginTop:    "4rem",
    },
  };

  const features = [
    { icon: "🔍", title: "Deep Vulnerability Scanning",
      text: "Detects XSS, SQL Injection, IDOR, SSRF, open ports, missing security headers and 30+ vulnerability types automatically." },
    { icon: "🤖", title: "AI-Powered Reports",
      text: "Every finding explained in plain English with a risk score 0–10 and step-by-step fix recommendations — no security expertise needed." },
    { icon: "📄", title: "Professional Reports",
      text: "Download PDF and HTML reports to share with your team, clients, or compliance auditors instantly." },
    { icon: "⚡", title: "Fast Results",
      text: "Complete website security scan in under 5 minutes. Just enter your URL and get results." },
    { icon: "🌐", title: "Network Scanning",
      text: "Discovers open ports and dangerous exposed services like Redis, MongoDB, RDP, and Docker." },
    { icon: "🔐", title: "API Security Testing",
      text: "Tests REST APIs for broken authentication, missing rate limiting, CORS misconfiguration and exposed documentation." },
  ];

  const plans = [
    {
      name: "FREE", price: "₹0", sub: "/month", popular: false,
      features: ["2 scans/month", "Header & SSL check", "Basic HTML report", "Email support"],
      btn: "Get Started Free", outline: true,
    },
    {
      name: "STARTER", price: "₹999", sub: "/month", popular: true,
      features: ["10 scans/month", "All 6 scan modules", "AI triage + risk scores", "PDF + HTML reports", "Priority support"],
      btn: "Get Starter →", outline: false,
    },
    {
      name: "PRO", price: "₹2,999", sub: "/month", popular: false,
      features: ["50 scans/month", "All modules + API access", "Scheduled weekly scans", "White-label reports", "Dedicated support"],
      btn: "Get Pro →", outline: false,
    },
    {
      name: "AGENCY", price: "₹4,999", sub: "/month", popular: false,
      features: ["Unlimited scans", "Multiple client portals", "Custom branding", "API integration", "1-on-1 onboarding"],
      btn: "Contact Us →", outline: false,
    },
  ];

  return (
    <div style={styles.page}>

      {/* NAV */}
      <nav style={styles.nav}>
        <div style={styles.logo}>🦅 HAWKEYE</div>
        <button style={styles.navBtn} onClick={onGetStarted}>
          Launch Dashboard →
        </button>
      </nav>

      {/* HERO */}
      <div style={styles.hero}>
        <div style={styles.heroLogo}>🦅 HAWKEYE</div>
        <div style={styles.heroSub}>AI-ASSISTED BUG HUNTING</div>
        <p style={styles.heroTagline}>
          Find security vulnerabilities in your website before hackers do.
          Automated scanning powered by AI — get a professional report in minutes.
        </p>
        <button style={styles.ctaBtn} onClick={onGetStarted}>
          Start Free Scan →
        </button>
        <p style={styles.ctaNote}>
          No credit card required · 2 free scans/month
        </p>
      </div>

      {/* STATS */}
      <div style={{ background: "#111" }}>
        <div style={styles.statsRow}>
          {[
            { num: "30+",  label: "VULNERABILITY CHECKS" },
            { num: "6",    label: "SCAN MODULES"         },
            { num: "AI",   label: "POWERED TRIAGE"       },
            { num: "134",  label: "TESTS PASSING"        },
          ].map(s => (
            <div key={s.label} style={styles.stat}>
              <div style={styles.statNum}>{s.num}</div>
              <div style={styles.statLabel}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* FEATURES */}
      <div style={styles.section}>
        <div style={styles.sectionTitle}>WHAT HAWKEYE DETECTS</div>
        <div style={styles.grid3}>
          {features.map(f => (
            <div key={f.title} style={styles.featureCard}>
              <div style={styles.featureIcon}>{f.icon}</div>
              <div style={styles.featureTitle}>{f.title}</div>
              <p style={styles.featureText}>{f.text}</p>
            </div>
          ))}
        </div>
      </div>

      {/* HOW IT WORKS */}
      <div style={styles.sectionDark}>
        <div style={{ maxWidth: "700px", margin: "0 auto", padding: "0 1rem" }}>
          <div style={styles.sectionTitle}>HOW IT WORKS</div>
          {[
            { n: "1", title: "Enter your URL",
              desc: "Type your website URL or IP address into the scanner." },
            { n: "2", title: "Select scan modules",
              desc: "Choose from Headers, Network, Web Vulnerabilities, and API Security." },
            { n: "3", title: "Get your report",
              desc: "AI analyzes findings and generates a plain-English report with fix steps." },
            { n: "4", title: "Fix and rescan",
              desc: "Follow the fix recommendations and rescan to verify everything is patched." },
          ].map(step => (
            <div key={step.n} style={styles.howStep}>
              <div style={styles.stepNum}>{step.n}</div>
              <div style={styles.stepText}>
                <div style={styles.stepTitle}>{step.title}</div>
                <div style={styles.stepDesc}>{step.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* PRICING */}
      <div style={{ ...styles.section, textAlign: "center" }}>
        <div style={styles.sectionTitle}>SIMPLE PRICING</div>
        <div style={styles.plansGrid}>
          {plans.map(plan => (
            <div key={plan.name}
              style={plan.popular ? styles.planPopular : styles.plan}>
              {plan.popular && (
                <div style={{ color: "#00FFFF", fontSize: "0.7rem",
                  letterSpacing: "2px", marginBottom: "8px" }}>
                  ⭐ MOST POPULAR
                </div>
              )}
              <div style={styles.planName}>{plan.name}</div>
              <div style={styles.planPrice}>
                {plan.price}
                <span style={styles.planPriceSub}>{plan.sub}</span>
              </div>
              <div style={{ marginTop: "1.2rem" }}>
                {plan.features.map(f => (
                  <div key={f} style={styles.planFeature}>
                    <span style={{ color: "#00FFFF" }}>✓</span> {f}
                  </div>
                ))}
              </div>
              <button
                style={plan.outline ? styles.planBtnOutline : styles.planBtn}
                onClick={onGetStarted}
              >
                {plan.btn}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* CTA BOTTOM */}
      <div style={{
        background:  "#0D1B2A",
        borderTop:   "1px solid #1E3A4A",
        borderBottom:"1px solid #1E3A4A",
        textAlign:   "center",
        padding:     "60px 2rem",
      }}>
        <h2 style={{ color: "#00FFFF", fontSize: "1.8rem",
          marginBottom: "1rem" }}>
          Ready to secure your website?
        </h2>
        <p style={{ color: "#888", marginBottom: "2rem" }}>
          Start with 2 free scans. No credit card required.
        </p>
        <button style={styles.ctaBtn} onClick={onGetStarted}>
          Start Free Scan →
        </button>
      </div>

      {/* FOOTER */}
      <div style={styles.footer}>
        © 2025 HawkEye Security · Built by Kalpin Patel ·
        github.com/kalpin05
        <br /><br />
        ⚠️ For authorized testing only.
        Users must have permission to scan target systems.
      </div>

    </div>
  );
}