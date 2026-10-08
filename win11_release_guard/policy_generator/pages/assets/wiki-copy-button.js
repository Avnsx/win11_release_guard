
    (function () {
      var blocks = document.querySelectorAll(".wiki-content pre");
      if (!blocks.length) return;
      function flash(btn, label, ok) {
        var original = btn.getAttribute("data-label") || "Copy";
        btn.textContent = label;
        btn.classList.toggle("is-copied", !!ok);
        window.setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove("is-copied");
        }, 1400);
      }
      function copyText(text, btn) {
        function fallback() {
          try {
            var ta = document.createElement("textarea");
            ta.value = text;
            ta.setAttribute("readonly", "");
            ta.style.position = "absolute";
            ta.style.left = "-9999px";
            document.body.appendChild(ta);
            ta.select();
            var ok = document.execCommand("copy");
            document.body.removeChild(ta);
            flash(btn, ok ? "Copied" : "Copy failed", ok);
          } catch (e) {
            flash(btn, "Copy failed", false);
          }
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            flash(btn, "Copied", true);
          }, fallback);
        } else {
          fallback();
        }
      }
      Array.prototype.forEach.call(blocks, function (pre) {
        if (pre.querySelector(".wiki-copy-btn")) return;
        var code = pre.querySelector("code");
        var text = code ? code.textContent : pre.textContent;
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "wiki-copy-btn";
        btn.textContent = "Copy";
        btn.setAttribute("data-label", "Copy");
        btn.setAttribute("aria-label", "Copy code to clipboard");
        btn.addEventListener("click", function () { copyText(text, btn); });
        pre.appendChild(btn);
      });
    })();
  
