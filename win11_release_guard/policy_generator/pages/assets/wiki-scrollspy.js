
    (function () {
      var sidebar = document.querySelector(".wiki-sidebar");
      var content = document.getElementById("wiki-content");
      if (!sidebar || !content) return;
      var currentPageLink = sidebar.querySelector('a.is-current-page[aria-current="page"]');
      var manualSidebarScrollUntil = 0;
      var autoScrollingSidebar = false;
      var allowSectionAutoAlign = false;
      var pendingSidebarNavigationHref = "";
      var sidebarNavigationStorageKey = "win11_release_guard.wikiSidebarScroll.v1";
      var prefersReducedMotion = false;
      try {
        prefersReducedMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
      } catch (error) {
        prefersReducedMotion = false;
      }

      function now() {
        return Date.now ? Date.now() : new Date().getTime();
      }

      function normalizedUrl(value) {
        try {
          return new URL(value, window.location.href);
        } catch (error) {
          return null;
        }
      }

      function sameDocumentUrl(left, right) {
        return !!(
          left &&
          right &&
          left.origin === right.origin &&
          left.pathname === right.pathname &&
          left.search === right.search &&
          left.hash === right.hash
        );
      }

      function rememberSidebarScrollForHref(href) {
        var destination = normalizedUrl(href);
        if (!destination) return;
        try {
          if (!window.sessionStorage) return;
          window.sessionStorage.setItem(sidebarNavigationStorageKey, JSON.stringify({
            href: destination.href,
            scrollTop: Math.max(0, Math.round(sidebar.scrollTop || 0)),
            savedAt: now()
          }));
        } catch (error) {
          return;
        }
      }

      function restoreSidebarNavigationPosition() {
        try {
          if (!window.sessionStorage) return false;
          var raw = window.sessionStorage.getItem(sidebarNavigationStorageKey);
          if (!raw) return false;
          var state = JSON.parse(raw);
          if (!state || typeof state.href !== "string" || typeof state.scrollTop !== "number") return false;
          if (state.savedAt && now() - state.savedAt > 30000) return false;
          if (!sameDocumentUrl(normalizedUrl(state.href), normalizedUrl(window.location.href))) return false;
          autoScrollingSidebar = true;
          sidebar.scrollTop = Math.max(0, Math.round(state.scrollTop));
          window.setTimeout(function () {
            autoScrollingSidebar = false;
          }, 80);
          return true;
        } catch (error) {
          return false;
        }
      }

      function markManualSidebarScroll() {
        if (!autoScrollingSidebar) manualSidebarScrollUntil = now() + 1200;
      }

      sidebar.addEventListener("wheel", markManualSidebarScroll, { passive: true });
      sidebar.addEventListener("touchstart", markManualSidebarScroll, { passive: true });
      sidebar.addEventListener("keydown", markManualSidebarScroll);
      sidebar.addEventListener("scroll", markManualSidebarScroll, { passive: true });
      sidebar.addEventListener("click", function (event) {
        var link = event.target && event.target.closest ? event.target.closest("a[href]") : null;
        if (!link || !sidebar.contains(link) || event.defaultPrevented) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        if ("button" in event && event.button !== 0) return;
        var href = link.getAttribute("href") || "";
        if (!href || href.charAt(0) === "#") return;
        pendingSidebarNavigationHref = href;
        rememberSidebarScrollForHref(href);
      });
      window.addEventListener("pagehide", function () {
        if (pendingSidebarNavigationHref) return;
        rememberSidebarScrollForHref(window.location.href);
      });
      var restoredSidebarNavigationPosition = restoreSidebarNavigationPosition();

      function sidebarAlignmentTargetForCurrentPage() {
        if (!currentPageLink) return null;
        var sourceNav = currentPageLink.closest ? currentPageLink.closest(".wiki-source-nav") : null;
        if (!sourceNav) return currentPageLink;
        return sourceNav.querySelector(".wiki-nav-group.is-current-group") || currentPageLink;
      }

      function sidebarTargetIsVisible(target) {
        var sidebarBox = sidebar.getBoundingClientRect();
        var targetBox = target.getBoundingClientRect();
        return targetBox.top >= sidebarBox.top + 8 && targetBox.bottom <= sidebarBox.bottom - 8;
      }

      function sidebarContentOffsetTop(target) {
        if (!sidebar.contains(target)) return 0;
        var sidebarBox = sidebar.getBoundingClientRect();
        var targetBox = target.getBoundingClientRect();
        return sidebar.scrollTop + targetBox.top - sidebarBox.top;
      }

      function sidebarScrollOffset() {
        return 10;
      }

      function alignSidebarTarget(target, force, behavior) {
        if (!target || !sidebar.contains(target)) return;
        if (!force && (now() < manualSidebarScrollUntil || sidebarTargetIsVisible(target))) return;
        var targetTop = sidebarContentOffsetTop(target) - sidebarScrollOffset();
        targetTop = Math.max(0, Math.round(targetTop));
        var scrollBehavior = behavior || (prefersReducedMotion ? "auto" : "smooth");
        autoScrollingSidebar = true;
        try {
          sidebar.scrollTo({ top: targetTop, behavior: scrollBehavior });
        } catch (error) {
          sidebar.scrollTop = targetTop;
        }
        window.setTimeout(function () {
          autoScrollingSidebar = false;
        }, scrollBehavior === "smooth" ? 360 : 80);
      }

      function initialSidebarAlignmentBehavior() {
        return restoredSidebarNavigationPosition && !prefersReducedMotion ? "smooth" : "auto";
      }

      function alignCurrentPageLink(behavior) {
        alignSidebarTarget(sidebarAlignmentTargetForCurrentPage(), true, behavior);
      }

      function isVersionMetaLink(link) {
        var node = link;
        while (node && node !== sidebar) {
          if (node.classList && node.classList.contains("version-meta")) return true;
          node = node.parentElement;
        }
        return false;
      }

      function samePageHash(link) {
        var href = link.getAttribute("href") || "";
        if (!href || isVersionMetaLink(link)) return "";
        if (href.charAt(0) === "#") return href;
        if (typeof URL === "undefined") return "";
        try {
          var url = new URL(href, window.location.href);
          if (url.origin !== window.location.origin || url.pathname !== window.location.pathname) return "";
          return url.hash || "";
        } catch (error) {
          return "";
        }
      }

      function hashId(hash) {
        try {
          return decodeURIComponent(hash.slice(1));
        } catch (error) {
          return hash.slice(1);
        }
      }

      var items = Array.prototype.slice.call(sidebar.querySelectorAll("a[href]")).map(function (link) {
        var hash = samePageHash(link);
        if (!hash || hash === "#") return null;
        var target = document.getElementById(hashId(hash));
        if (!target || !content.contains(target)) return null;
        return { link: link, item: link.closest ? link.closest("li") : null, target: target };
      }).filter(Boolean);
      if (!items.length) {
        alignCurrentPageLink(initialSidebarAlignmentBehavior());
        return;
      }

      function setActive(active, alignActive) {
        items.forEach(function (entry) {
          var selected = entry === active;
          entry.link.classList.toggle("is-active-section", selected);
          if (entry.item) entry.item.classList.toggle("is-active-section", selected);
          if (selected) {
            entry.link.setAttribute("aria-current", "location");
          } else {
            entry.link.removeAttribute("aria-current");
          }
        });
        if (alignActive && active) alignSidebarTarget(active.item || active.link, false);
      }

      function updateActiveSection(alignActive) {
        var activationLine = Math.min(window.innerHeight * 0.28, 180);
        var active = items[0];
        items.forEach(function (entry) {
          if (entry.target.getBoundingClientRect().top <= activationLine) active = entry;
        });
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
          active = items[items.length - 1];
        }
        setActive(active, alignActive);
        return active;
      }

      var requestFrame = window.requestAnimationFrame || function (callback) { return window.setTimeout(callback, 16); };
      var scheduled = false;
      function scheduleUpdate() {
        if (scheduled) return;
        scheduled = true;
        requestFrame(function () {
          scheduled = false;
          updateActiveSection(allowSectionAutoAlign);
        });
      }

      window.addEventListener("scroll", scheduleUpdate, { passive: true });
      window.addEventListener("resize", scheduleUpdate);
      window.addEventListener("hashchange", function () {
        allowSectionAutoAlign = true;
        scheduleUpdate();
      });
      if ("IntersectionObserver" in window) {
        var observer = new IntersectionObserver(scheduleUpdate, { rootMargin: "-18% 0px -70% 0px", threshold: [0, 1] });
        items.forEach(function (entry) { observer.observe(entry.target); });
      }
      var initialActive = updateActiveSection(false);
      if (window.location.hash && initialActive) {
        alignSidebarTarget(initialActive.item || initialActive.link, true, initialSidebarAlignmentBehavior());
      } else {
        alignCurrentPageLink(initialSidebarAlignmentBehavior());
      }
      window.setTimeout(function () {
        allowSectionAutoAlign = true;
      }, 300);
    })();
  
