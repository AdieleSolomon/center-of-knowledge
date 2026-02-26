const App = (() => {
  const WHATSAPP_PHONE = "2349072560420";
  const CONTACT_EMAIL = "Wisdomadiele57@gmail.com";

  const isLocalHost =
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

  const getConfiguredApiBase = () => {
    const windowValue =
      window.APP_CONFIG?.API_BASE || window.__APP_CONFIG__?.API_BASE;
    if (typeof windowValue === "string" && windowValue.trim()) {
      return windowValue.trim().replace(/\/$/, "");
    }

    const metaValue = document
      .querySelector('meta[name="api-base-url"]')
      ?.getAttribute("content");
    if (typeof metaValue === "string" && metaValue.trim()) {
      return metaValue.trim().replace(/\/$/, "");
    }

    return null;
  };

  const configuredApiBase = getConfiguredApiBase();
  const API_BASE =
    configuredApiBase ||
    (isLocalHost ? "http://localhost:5501/api" : `${window.location.origin}/api`);
  const BACKEND_ORIGIN = API_BASE.replace(/\/api\/?$/, "");

  const state = {
    token: localStorage.getItem("authToken") || localStorage.getItem("adminToken"),
    user: null,
  };

  const fallbackResources = [
    {
      title: "Foundations of Christian Faith",
      description:
        "A structured guide for growing confidence in Christ and in the authority of scripture.",
      category: "teaching",
      type: "guide",
      link: "#contact",
    },
    {
      title: "Strategic Patterns of Prayer",
      description:
        "A practical prayer framework for families, leaders, and ministry teams.",
      category: "prayer",
      type: "study",
      link: "#contact",
    },
    {
      title: "Leadership with Integrity",
      description:
        "Biblical leadership principles for influence, discipline, stewardship, and service.",
      category: "leadership",
      type: "teaching",
      link: "#contact",
    },
  ];

  const ui = {
    header: document.getElementById("siteHeader"),
    navToggle: document.getElementById("navToggle"),
    mainNav: document.getElementById("mainNav"),
    openAuthBtn: document.getElementById("openAuthBtn"),
    resourceLoginBtn: document.getElementById("resourceLoginBtn"),
    logoutBtn: document.getElementById("logoutBtn"),
    userBadge: document.getElementById("userBadge"),
    userName: document.getElementById("userName"),
    userRole: document.getElementById("userRole"),
    userAvatar: document.getElementById("userAvatar"),
    resourceGrid: document.getElementById("resourceGrid"),
    resourceNotice: document.getElementById("resourceNotice"),
    authModal: document.getElementById("authModal"),
    closeAuthBtn: document.getElementById("closeAuthBtn"),
    loginForm: document.getElementById("loginForm"),
    loginEmail: document.getElementById("loginEmail"),
    loginPassword: document.getElementById("loginPassword"),
    loginSubmitBtn: document.getElementById("loginSubmitBtn"),
    authMessage: document.getElementById("authMessage"),
    prayerForm: document.getElementById("prayerForm"),
    prayerName: document.getElementById("prayerName"),
    prayerRequest: document.getElementById("prayerRequest"),
    prayerAnonymous: document.getElementById("prayerAnonymous"),
    contactForm: document.getElementById("contactForm"),
    contactName: document.getElementById("contactName"),
    contactEmail: document.getElementById("contactEmail"),
    contactSubject: document.getElementById("contactSubject"),
    contactMessage: document.getElementById("contactMessage"),
    year: document.getElementById("year"),
  };

  function init() {
    setYear();
    setupScrollHeader();
    setupMobileNav();
    setupActiveNavTracking();
    setupRevealAnimations();
    setupModal();
    setupSessionButtons();
    setupPrayerForm();
    setupContactForm();
    setupLoginForm();

    updateAuthUI();
    hydrateSession().finally(loadResources);
  }

  function setYear() {
    if (ui.year) {
      ui.year.textContent = String(new Date().getFullYear());
    }
  }

  function setupScrollHeader() {
    if (!ui.header) return;

    const handleScroll = () => {
      if (window.scrollY > 20) {
        ui.header.classList.add("scrolled");
      } else {
        ui.header.classList.remove("scrolled");
      }
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
  }

  function setupMobileNav() {
    if (!ui.navToggle || !ui.mainNav) return;

    ui.navToggle.addEventListener("click", () => {
      ui.mainNav.classList.toggle("open");
    });

    ui.mainNav.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        ui.mainNav.classList.remove("open");
      });
    });
  }

  function setupActiveNavTracking() {
    const navLinks = Array.from(document.querySelectorAll(".main-nav a"));
    const sectionMap = navLinks
      .map((link) => {
        const href = link.getAttribute("href") || "";
        if (!href.startsWith("#")) return null;
        const section = document.querySelector(href);
        if (!section) return null;
        return { link, section };
      })
      .filter(Boolean);

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;

          const found = sectionMap.find((item) => item.section === entry.target);
          if (!found) return;

          navLinks.forEach((link) => link.classList.remove("active"));
          found.link.classList.add("active");
        });
      },
      {
        rootMargin: "-45% 0px -45% 0px",
        threshold: 0.01,
      },
    );

    sectionMap.forEach((item) => observer.observe(item.section));
  }

  function setupRevealAnimations() {
    const targets = document.querySelectorAll("[data-reveal]:not(.revealed)");
    if (!targets.length) return;

    const observer = new IntersectionObserver(
      (entries, obs) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("revealed");
          obs.unobserve(entry.target);
        });
      },
      {
        threshold: 0.14,
        rootMargin: "0px 0px -40px 0px",
      },
    );

    targets.forEach((item, index) => {
      item.style.transitionDelay = `${Math.min(index * 50, 320)}ms`;
      observer.observe(item);
    });
  }

  function setupModal() {
    if (!ui.authModal) return;

    const open = () => {
      ui.authModal.classList.add("open");
      ui.authModal.setAttribute("aria-hidden", "false");
      ui.loginEmail?.focus();
    };

    const close = () => {
      ui.authModal.classList.remove("open");
      ui.authModal.setAttribute("aria-hidden", "true");
      setAuthMessage("");
    };

    ui.openAuthBtn?.addEventListener("click", open);
    ui.resourceLoginBtn?.addEventListener("click", open);
    ui.closeAuthBtn?.addEventListener("click", close);

    ui.authModal.addEventListener("click", (event) => {
      if (event.target === ui.authModal) {
        close();
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        close();
      }
    });

    ui.logoutBtn?.addEventListener("click", () => {
      clearSession();
      updateAuthUI();
      loadResources();
      notify("You have been logged out.", "success");
    });

    ui.authModal.closeModal = close;
  }

  function setupSessionButtons() {
    document.querySelectorAll(".session-btn").forEach((button) => {
      button.addEventListener("click", () => {
        const sessionType = button.dataset.session || "prayer";
        const message =
          sessionType === "counseling"
            ? "Hello Pastor, I would like to book a counseling session."
            : "Hello Pastor, I would like to book a prayer session.";

        openWhatsApp(message);
      });
    });
  }

  function setupPrayerForm() {
    if (!ui.prayerForm) return;

    ui.prayerForm.addEventListener("submit", (event) => {
      event.preventDefault();

      const request = ui.prayerRequest?.value.trim();
      if (!request) {
        notify("Please enter your prayer request.", "error");
        return;
      }

      const anonymous = ui.prayerAnonymous?.checked;
      const name = anonymous
        ? "Anonymous"
        : ui.prayerName?.value.trim() || "Website Visitor";

      const message = [
        "Prayer Request:",
        `Name: ${name}`,
        `Request: ${request}`,
      ].join("\n");

      openWhatsApp(message);

      ui.prayerForm.reset();
      notify("Prayer request prepared on WhatsApp.", "success");
    });
  }

  function setupContactForm() {
    if (!ui.contactForm) return;

    ui.contactForm.addEventListener("submit", (event) => {
      event.preventDefault();

      const name = ui.contactName?.value.trim();
      const email = ui.contactEmail?.value.trim();
      const subject = ui.contactSubject?.value.trim();
      const message = ui.contactMessage?.value.trim();

      if (!name || !email || !subject || !message) {
        notify("Please complete all contact fields.", "error");
        return;
      }

      const body = [
        `Name: ${name}`,
        `Email: ${email}`,
        "",
        message,
      ].join("\n");

      const mailtoUrl = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
      window.location.href = mailtoUrl;

      ui.contactForm.reset();
      notify("Opening your email app to send this message.", "success");
    });
  }

  function setupLoginForm() {
    if (!ui.loginForm) return;

    ui.loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const email = ui.loginEmail?.value.trim();
      const password = ui.loginPassword?.value;

      if (!email || !password) {
        setAuthMessage("Please enter both email and password.", true);
        return;
      }

      setAuthLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (!response.ok || !data?.token) {
          throw new Error(data?.error || "Unable to sign in.");
        }

        state.token = data.token;
        state.user = data.user || null;

        localStorage.setItem("authToken", data.token);

        updateAuthUI();
        loadResources();

        setAuthMessage("Sign-in successful. Resource sync is now active.", false);
        notify("You are signed in successfully.", "success");

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.loginForm?.reset();
        }, 500);
      } catch (error) {
        setAuthMessage(error.message || "Login failed.", true);
      } finally {
        setAuthLoading(false);
      }
    });
  }

  function setAuthLoading(isLoading) {
    if (!ui.loginSubmitBtn) return;
    ui.loginSubmitBtn.disabled = isLoading;
    ui.loginSubmitBtn.textContent = isLoading ? "Signing In..." : "Sign In";
  }

  function setAuthMessage(text, isError = false) {
    if (!ui.authMessage) return;
    ui.authMessage.textContent = text;
    ui.authMessage.className = "auth-message";
    if (text) {
      ui.authMessage.classList.add(isError ? "error" : "success");
    }
  }

  async function hydrateSession() {
    if (!state.token) return;

    try {
      const response = await fetch(`${API_BASE}/auth/validate`, {
        headers: {
          Authorization: `Bearer ${state.token}`,
        },
      });

      const data = await response.json();

      if (!response.ok || !data?.user) {
        throw new Error("Session expired");
      }

      state.user = data.user;
      updateAuthUI();
    } catch (error) {
      clearSession();
      updateAuthUI();
    }
  }

  function clearSession() {
    state.token = null;
    state.user = null;

    localStorage.removeItem("authToken");
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminEmail");
  }

  function updateAuthUI() {
    const loggedIn = Boolean(state.token && state.user);

    if (ui.userBadge) {
      ui.userBadge.hidden = !loggedIn;
    }

    if (ui.logoutBtn) {
      ui.logoutBtn.hidden = !loggedIn;
    }

    if (ui.resourceLoginBtn) {
      ui.resourceLoginBtn.hidden = loggedIn;
    }

    if (ui.openAuthBtn) {
      ui.openAuthBtn.hidden = loggedIn;
    }

    if (loggedIn) {
      const displayName = state.user.username || state.user.email || "Member";
      const role = state.user.role || "member";

      if (ui.userName) ui.userName.textContent = displayName;
      if (ui.userRole) ui.userRole.textContent = role;
      if (ui.userAvatar) {
        ui.userAvatar.textContent = displayName.charAt(0).toUpperCase();
      }
    }
  }

  async function loadResources() {
    if (!ui.resourceGrid) return;

    renderResources(fallbackResources, false);

    if (!state.token) {
      setResourceNotice(
        "Sign in to synchronize ministry materials. Showing curated resources for now.",
        "warning",
      );
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/materials?limit=6&page=1`, {
        headers: {
          Authorization: `Bearer ${state.token}`,
        },
      });

      const data = await response.json();

      if (response.status === 403) {
        setResourceNotice(
          "Your account is signed in, but synchronized materials are currently restricted to approved admin sessions.",
          "warning",
        );
        return;
      }

      if (!response.ok) {
        throw new Error(data?.error || "Failed to load resources.");
      }

      const materials = Array.isArray(data.materials) ? data.materials : [];
      if (!materials.length) {
        setResourceNotice(
          "No uploaded materials are available yet. Showing curated resources.",
          "warning",
        );
        return;
      }

      const normalized = materials.slice(0, 6).map((item) => ({
        title: item.title || "Untitled Material",
        description: item.description || "No description available.",
        category: item.category || "resource",
        type: item.type || "file",
        link: resolveFileUrl(item.file_url),
      }));

      renderResources(normalized, true);
      setResourceNotice("Latest ministry materials synchronized successfully.", "success");
    } catch (error) {
      setResourceNotice(
        "Unable to synchronize materials at the moment. Showing curated resources.",
        "error",
      );
    }
  }

  function resolveFileUrl(fileUrl) {
    if (!fileUrl) return "#";
    if (/^https?:\/\//i.test(fileUrl)) return fileUrl;
    const normalizedPath = fileUrl.startsWith("/")
      ? fileUrl
      : `/${fileUrl.replace(/^\.?\//, "")}`;
    return `${BACKEND_ORIGIN}${normalizedPath}`;
  }

  function renderResources(resources, fromApi) {
    if (!ui.resourceGrid) return;

    ui.resourceGrid.innerHTML = resources
      .map((item) => {
        const category = sanitize(item.category || "resource");
        const type = sanitize(item.type || "file");
        const title = sanitize(item.title || "Resource");
        const description = sanitize(item.description || "");
        const href = sanitize(item.link || "#");

        const isExternal = href.startsWith("http");
        const targetAttr = isExternal ? 'target="_blank" rel="noopener noreferrer"' : "";

        return `
          <article class="resource-card" data-reveal>
            <div class="resource-meta">
              <span>${category}</span>
              <span>${type}</span>
            </div>
            <h3>${title}</h3>
            <p>${description}</p>
            <a class="resource-link" href="${href}" ${targetAttr}>
              ${fromApi ? "Open Material" : "Preview"}
              <i class="fa-solid fa-arrow-right"></i>
            </a>
          </article>
        `;
      })
      .join("");

    setupRevealAnimations();
  }

  function setResourceNotice(text, tone = "") {
    if (!ui.resourceNotice) return;

    ui.resourceNotice.textContent = text;
    ui.resourceNotice.className = "resource-notice";

    if (tone === "warning") ui.resourceNotice.classList.add("is-warning");
    if (tone === "error") ui.resourceNotice.classList.add("is-error");
    if (tone === "success") ui.resourceNotice.classList.add("is-success");
  }

  function openWhatsApp(message) {
    const text = encodeURIComponent(message);
    window.open(`https://wa.me/${WHATSAPP_PHONE}?text=${text}`, "_blank");
  }

  function sanitize(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function notify(message, tone = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${tone}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    requestAnimationFrame(() => {
      toast.classList.add("show");
    });

    setTimeout(() => {
      toast.classList.remove("show");
      setTimeout(() => toast.remove(), 220);
    }, 2600);
  }

  return { init };
})();

window.addEventListener("DOMContentLoaded", App.init);
