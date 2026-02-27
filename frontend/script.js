document.documentElement.classList.add("js");

const App = (() => {
  const WHATSAPP_PHONE = "2349072560420";
  const CONTACT_EMAIL = "Wisdomadiele57@gmail.com";
  const DEFAULT_MAP_QUERY = "Center of Knowledge and Spiritual Enrichment";

  const getConfigString = (key) => {
    const value = window.APP_CONFIG?.[key] ?? window.__APP_CONFIG__?.[key];
    return typeof value === "string" ? value.trim() : "";
  };

  const GOOGLE_ANALYTICS_ID = getConfigString("GOOGLE_ANALYTICS_ID");
  const GOOGLE_MAPS_EMBED_URL = getConfigString("GOOGLE_MAPS_EMBED_URL");
  const GOOGLE_MAPS_DIRECTIONS_URL = getConfigString("GOOGLE_MAPS_DIRECTIONS_URL");

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
    authMode: "login",
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
    openAuthBtns: Array.from(document.querySelectorAll("[data-open-auth]")),
    resourceLoginBtn: document.getElementById("resourceLoginBtn"),
    logoutBtn: document.getElementById("logoutBtn"),
    userBadge: document.getElementById("userBadge"),
    userName: document.getElementById("userName"),
    userRole: document.getElementById("userRole"),
    userAvatar: document.getElementById("userAvatar"),
    resourceGrid: document.getElementById("resourceGrid"),
    resourceNotice: document.getElementById("resourceNotice"),
    authModal: document.getElementById("authModal"),
    authModalTitle: document.getElementById("authModalTitle"),
    authModalSubtitle: document.getElementById("authModalSubtitle"),
    authTabs: Array.from(document.querySelectorAll(".auth-tab")),
    authModeButtons: Array.from(document.querySelectorAll("[data-auth-mode]")),
    authViews: Array.from(document.querySelectorAll(".auth-view")),
    closeAuthBtn: document.getElementById("closeAuthBtn"),
    loginForm: document.getElementById("loginForm"),
    loginEmail: document.getElementById("loginEmail"),
    loginPassword: document.getElementById("loginPassword"),
    loginSubmitBtn: document.getElementById("loginSubmitBtn"),
    registerForm: document.getElementById("registerForm"),
    registerUsername: document.getElementById("registerUsername"),
    registerEmail: document.getElementById("registerEmail"),
    registerPassword: document.getElementById("registerPassword"),
    registerConfirmPassword: document.getElementById("registerConfirmPassword"),
    registerSubmitBtn: document.getElementById("registerSubmitBtn"),
    recoverForm: document.getElementById("recoverForm"),
    recoverEmail: document.getElementById("recoverEmail"),
    recoverCode: document.getElementById("recoverCode"),
    recoverPassword: document.getElementById("recoverPassword"),
    recoverConfirmPassword: document.getElementById("recoverConfirmPassword"),
    requestRecoveryBtn: document.getElementById("requestRecoveryBtn"),
    recoverSubmitBtn: document.getElementById("recoverSubmitBtn"),
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
    googleMapEmbed: document.getElementById("googleMapEmbed"),
    googleDirectionsLink: document.getElementById("googleDirectionsLink"),
    year: document.getElementById("year"),
  };

  function init() {
    setupGoogleAnalytics();
    setupGoogleMap();
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
    setupRegisterForm();
    setupRecoverForm();

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

    const closeMenu = () => {
      ui.mainNav.classList.remove("open");
      ui.navToggle.setAttribute("aria-expanded", "false");
    };

    ui.navToggle.setAttribute("aria-expanded", "false");
    ui.navToggle.setAttribute("aria-controls", "mainNav");

    ui.navToggle.addEventListener("click", () => {
      const isOpen = ui.mainNav.classList.toggle("open");
      ui.navToggle.setAttribute("aria-expanded", String(isOpen));
    });

    ui.mainNav.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        closeMenu();
        trackEvent("nav_click", { label: link.textContent?.trim() || "navigation" });
      });
    });

    document.addEventListener("click", (event) => {
      if (!ui.mainNav.classList.contains("open")) return;

      const target = event.target;
      if (ui.mainNav.contains(target) || ui.navToggle.contains(target)) return;

      closeMenu();
    });

    window.addEventListener("resize", () => {
      if (window.innerWidth > 900) {
        closeMenu();
      }
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

    if (!sectionMap.length || !("IntersectionObserver" in window)) {
      return;
    }

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
    if (!("IntersectionObserver" in window)) {
      targets.forEach((item) => item.classList.add("revealed"));
      return;
    }

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

    const open = (mode = "login") => {
      switchAuthMode(mode);
      ui.authModal.classList.add("open");
      ui.authModal.setAttribute("aria-hidden", "false");
      ui.mainNav?.classList.remove("open");
      ui.navToggle?.setAttribute("aria-expanded", "false");
      focusAuthField();
    };

    const close = () => {
      ui.authModal.classList.remove("open");
      ui.authModal.setAttribute("aria-hidden", "true");
      setAuthMessage("");
    };

    switchAuthMode("login");

    ui.openAuthBtns.forEach((button) => {
      button.addEventListener("click", () => {
        open(button.dataset.openAuthMode || "login");
      });
    });
    ui.resourceLoginBtn?.addEventListener("click", () => {
      open("login");
    });
    ui.authModeButtons.forEach((button) => {
      button.addEventListener("click", () => {
        switchAuthMode(button.dataset.authMode || "login");
      });
    });
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
    ui.authModal.openModal = open;
  }

  function switchAuthMode(mode = "login") {
    const allowedModes = new Set(["login", "register", "recover"]);
    const nextMode = allowedModes.has(mode) ? mode : "login";
    state.authMode = nextMode;

    const authText = {
      login: {
        title: "Member Sign-In",
        subtitle: "Sign in to access synchronized ministry resources.",
      },
      register: {
        title: "Create Member Account",
        subtitle: "Register with your details to access members-only resources.",
      },
      recover: {
        title: "Recover Password",
        subtitle:
          "Request a recovery code, then set a new password for your account.",
      },
    };

    ui.authViews.forEach((view) => {
      view.hidden = view.dataset.authView !== nextMode;
    });

    ui.authTabs.forEach((tab) => {
      const active = tab.dataset.authMode === nextMode;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
    });

    if (ui.authModalTitle) {
      ui.authModalTitle.textContent = authText[nextMode].title;
    }
    if (ui.authModalSubtitle) {
      ui.authModalSubtitle.textContent = authText[nextMode].subtitle;
    }

    setAuthMessage("");
    focusAuthField();
  }

  function focusAuthField() {
    const focusByMode = {
      login: ui.loginEmail,
      register: ui.registerUsername,
      recover: ui.recoverEmail,
    };

    requestAnimationFrame(() => {
      focusByMode[state.authMode]?.focus?.();
    });
  }

  function setupSessionButtons() {
    document.querySelectorAll(".session-btn").forEach((button) => {
      button.addEventListener("click", () => {
        const sessionType = button.dataset.session || "prayer";
        const message =
          sessionType === "counseling"
            ? "Hello Pastor, I would like to book a counseling session."
            : "Hello Pastor, I would like to book a prayer session.";

        openWhatsApp(
          message,
          sessionType === "counseling" ? "counseling_session" : "prayer_session",
        );
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

      openWhatsApp(message, "prayer_form");

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
      trackEvent("contact_email_prepare", { subject });

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
        setAuthMessage("Please enter email/username and password.", true);
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
        trackEvent("login_success", { method: "email_password" });

        setAuthMessage("Sign-in successful. Resource sync is now active.", false);
        notify("You are signed in successfully.", "success");

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.loginForm?.reset();
        }, 500);
      } catch (error) {
        trackEvent("login_failed", {
          reason: String(error.message || "unknown_error").slice(0, 120),
        });
        setAuthMessage(error.message || "Login failed.", true);
      } finally {
        setAuthLoading(false);
      }
    });
  }

  function setupRegisterForm() {
    if (!ui.registerForm) return;

    ui.registerForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const username = ui.registerUsername?.value.trim();
      const email = ui.registerEmail?.value.trim();
      const password = ui.registerPassword?.value || "";
      const confirmPassword = ui.registerConfirmPassword?.value || "";

      if (!username || !email || !password || !confirmPassword) {
        setAuthMessage("Please complete all registration fields.", true);
        return;
      }

      if (password.length < 8) {
        setAuthMessage("Password must be at least 8 characters long.", true);
        return;
      }

      if (password !== confirmPassword) {
        setAuthMessage("Password confirmation does not match.", true);
        return;
      }

      setRegisterLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
            email,
            password,
            confirmPassword,
          }),
        });

        const data = await response.json();

        if (!response.ok || !data?.token) {
          throw new Error(data?.error || "Unable to create account.");
        }

        state.token = data.token;
        state.user = data.user || null;
        localStorage.setItem("authToken", data.token);

        updateAuthUI();
        loadResources();
        notify("Registration successful. You are now signed in.", "success");
        setAuthMessage("Account created successfully.", false);
        trackEvent("register_success", { method: "email_password" });

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.registerForm?.reset();
        }, 500);
      } catch (error) {
        trackEvent("register_failed", {
          reason: String(error.message || "unknown_error").slice(0, 120),
        });
        setAuthMessage(error.message || "Registration failed.", true);
      } finally {
        setRegisterLoading(false);
      }
    });
  }

  function setupRecoverForm() {
    if (!ui.recoverForm) return;

    ui.requestRecoveryBtn?.addEventListener("click", async () => {
      const email = ui.recoverEmail?.value.trim();
      if (!email) {
        setAuthMessage("Enter your account email before requesting a code.", true);
        return;
      }

      setRecoveryRequestLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/forgot-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data?.error || "Unable to request recovery code.");
        }

        if (data?.recovery_code && ui.recoverCode) {
          ui.recoverCode.value = data.recovery_code;
          setAuthMessage(
            "Recovery code generated. Use it now before it expires.",
            false,
          );
        } else {
          setAuthMessage(data?.message || "Recovery instructions have been sent.", false);
        }
      } catch (error) {
        setAuthMessage(error.message || "Failed to request recovery code.", true);
      } finally {
        setRecoveryRequestLoading(false);
      }
    });

    ui.recoverForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const email = ui.recoverEmail?.value.trim();
      const recoveryCode = ui.recoverCode?.value.trim();
      const newPassword = ui.recoverPassword?.value || "";
      const confirmPassword = ui.recoverConfirmPassword?.value || "";

      if (!email || !recoveryCode || !newPassword || !confirmPassword) {
        setAuthMessage("Please complete all password recovery fields.", true);
        return;
      }

      if (newPassword.length < 8) {
        setAuthMessage("New password must be at least 8 characters long.", true);
        return;
      }

      if (newPassword !== confirmPassword) {
        setAuthMessage("Password confirmation does not match.", true);
        return;
      }

      setRecoverSubmitLoading(true);
      setAuthMessage("");

      try {
        const response = await fetch(`${API_BASE}/auth/reset-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            recoveryCode,
            newPassword,
            confirmPassword,
          }),
        });

        const data = await response.json();

        if (!response.ok || !data?.token) {
          throw new Error(data?.error || "Failed to reset password.");
        }

        state.token = data.token;
        state.user = data.user || null;
        localStorage.setItem("authToken", data.token);

        updateAuthUI();
        loadResources();
        notify("Password reset successful. You are signed in.", "success");
        setAuthMessage("Password reset successful.", false);
        trackEvent("password_reset_success", { source: "self_service" });

        setTimeout(() => {
          ui.authModal?.closeModal?.();
          ui.recoverForm?.reset();
        }, 500);
      } catch (error) {
        trackEvent("password_reset_failed", {
          reason: String(error.message || "unknown_error").slice(0, 120),
        });
        setAuthMessage(error.message || "Password reset failed.", true);
      } finally {
        setRecoverSubmitLoading(false);
      }
    });
  }

  function setAuthLoading(isLoading) {
    if (!ui.loginSubmitBtn) return;
    ui.loginSubmitBtn.disabled = isLoading;
    ui.loginSubmitBtn.textContent = isLoading ? "Signing In..." : "Sign In";
  }

  function setRegisterLoading(isLoading) {
    if (!ui.registerSubmitBtn) return;
    ui.registerSubmitBtn.disabled = isLoading;
    ui.registerSubmitBtn.textContent = isLoading
      ? "Creating Account..."
      : "Create Account";
  }

  function setRecoveryRequestLoading(isLoading) {
    if (!ui.requestRecoveryBtn) return;
    ui.requestRecoveryBtn.disabled = isLoading;
    ui.requestRecoveryBtn.textContent = isLoading
      ? "Generating Code..."
      : "Request Recovery Code";
  }

  function setRecoverSubmitLoading(isLoading) {
    if (!ui.recoverSubmitBtn) return;
    ui.recoverSubmitBtn.disabled = isLoading;
    ui.recoverSubmitBtn.textContent = isLoading
      ? "Resetting Password..."
      : "Reset Password";
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

    ui.openAuthBtns.forEach((button) => {
      button.hidden = loggedIn;
    });

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

    ui.resourceGrid.innerHTML = "";

    try {
      const fetchMaterials = async (token = null) => {
        const headers = token ? { Authorization: `Bearer ${token}` } : {};
        const response = await fetch(`${API_BASE}/materials?limit=6&page=1`, {
          headers,
        });
        const data = await response
          .json()
          .catch(() => ({ error: "Unexpected server response format." }));
        return { response, data };
      };

      let { response, data } = await fetchMaterials(state.token || null);

      if ((response.status === 401 || response.status === 403) && state.token) {
        clearSession();
        updateAuthUI();
        ({ response, data } = await fetchMaterials(null));
      }

      if (response.status === 401 || response.status === 403) {
        setResourceNotice(
          "Sign in to synchronize uploaded materials. Showing curated resources for now.",
          "warning",
        );
        renderResources(fallbackResources, false);
        return;
      }

      if (!response.ok) {
        throw new Error(data?.error || "Failed to load resources.");
      }
      if (!data || data.success !== true) {
        throw new Error("Invalid response from materials endpoint.");
      }

      const materials = Array.isArray(data.materials) ? data.materials : [];
      if (!materials.length) {
        setResourceNotice(
          "No uploaded materials are available yet. Showing curated resources.",
          "warning",
        );
        renderResources(fallbackResources, false);
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
      setResourceNotice(
        `Latest ministry materials (${materials.length} available).`,
        "success",
      );
    } catch (error) {
      setResourceNotice(
        "Unable to load uploaded materials at the moment. Showing curated resources.",
        "error",
      );
      renderResources(fallbackResources, false);
    }
  }

  function resolveFileUrl(fileUrl) {
    if (!fileUrl) return "#contact";
    if (/^https?:\/\//i.test(fileUrl)) return fileUrl;
    const normalizedPath = String(fileUrl)
      .replace(/\\/g, "/")
      .replace(/^\.?\/*/, "");
    if (!normalizedPath) return "#contact";
    return `${BACKEND_ORIGIN}/${normalizedPath}`;
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
            <a class="resource-link" href="${href}" data-resource-title="${title}" ${targetAttr}>
              ${fromApi ? "Open Material" : "Preview"}
              <i class="fa-solid fa-arrow-right"></i>
            </a>
          </article>
        `;
      })
      .join("");

    setupRevealAnimations();
    ui.resourceGrid.querySelectorAll(".resource-link").forEach((link) => {
      link.addEventListener("click", () => {
        trackEvent("resource_open", {
          title: link.dataset.resourceTitle || "resource",
          source: fromApi ? "api" : "fallback",
        });
      });
    });
  }

  function setResourceNotice(text, tone = "") {
    if (!ui.resourceNotice) return;

    ui.resourceNotice.textContent = text;
    ui.resourceNotice.className = "resource-notice";

    if (tone === "warning") ui.resourceNotice.classList.add("is-warning");
    if (tone === "error") ui.resourceNotice.classList.add("is-error");
    if (tone === "success") ui.resourceNotice.classList.add("is-success");
  }

  function openWhatsApp(message, source = "direct") {
    const text = encodeURIComponent(message);
    trackEvent("whatsapp_open", { source });
    window.open(`https://wa.me/${WHATSAPP_PHONE}?text=${text}`, "_blank");
  }

  function setupGoogleMap() {
    if (!ui.googleMapEmbed && !ui.googleDirectionsLink) return;

    const query = encodeURIComponent(DEFAULT_MAP_QUERY);
    const embedUrl =
      GOOGLE_MAPS_EMBED_URL ||
      `https://www.google.com/maps?q=${query}&output=embed`;
    const directionsUrl =
      GOOGLE_MAPS_DIRECTIONS_URL ||
      `https://www.google.com/maps/search/?api=1&query=${query}`;

    if (ui.googleMapEmbed) {
      ui.googleMapEmbed.src = embedUrl;
    }

    if (ui.googleDirectionsLink) {
      ui.googleDirectionsLink.href = directionsUrl;
      ui.googleDirectionsLink.addEventListener("click", () => {
        trackEvent("google_maps_open", { source: "contact_section" });
      });
    }
  }

  function setupGoogleAnalytics() {
    if (!GOOGLE_ANALYTICS_ID) return;

    if (typeof window.gtag === "function") {
      window.gtag("config", GOOGLE_ANALYTICS_ID, { anonymize_ip: true });
      return;
    }

    const tagScript = document.createElement("script");
    tagScript.async = true;
    tagScript.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(GOOGLE_ANALYTICS_ID)}`;
    document.head.appendChild(tagScript);

    window.dataLayer = window.dataLayer || [];
    window.gtag = function gtag() {
      window.dataLayer.push(arguments);
    };

    window.gtag("js", new Date());
    window.gtag("config", GOOGLE_ANALYTICS_ID, {
      anonymize_ip: true,
      transport_type: "beacon",
    });
  }

  function trackEvent(eventName, params = {}) {
    if (typeof window.gtag !== "function") return;
    window.gtag("event", eventName, params);
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
