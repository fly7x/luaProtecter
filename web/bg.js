(function () {
  var canvas = document.getElementById("bg-grid");
  if (!canvas) return;
  var ctx = canvas.getContext("2d");
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var cells = [];
  var cell = 46;
  var hexChars = "0123456789abcdef";

  function byte() {
    return hexChars[Math.floor(Math.random() * 16)] + hexChars[Math.floor(Math.random() * 16)];
  }

  function size() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    var cols = Math.ceil(canvas.width / cell) + 1;
    var rows = Math.ceil(canvas.height / cell) + 1;
    cells = [];
    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < cols; c++) {
        cells.push({
          x: c * cell,
          y: r * cell,
          v: byte(),
          t: Math.random() * Math.PI * 2,
          hue: Math.random() < 0.5 ? "139,123,255" : "34,211,238"
        });
      }
    }
  }
  window.addEventListener("resize", size);
  size();

  if (reduce) {
    ctx.font = "10px monospace";
    ctx.fillStyle = "rgba(139,123,255,.035)";
    cells.forEach(function (p) { ctx.fillText(p.v, p.x, p.y); });
    return;
  }

  function frame(t) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.font = "10px 'IBM Plex Mono', monospace";
    for (var i = 0; i < cells.length; i++) {
      var p = cells[i];
      var a = 0.03 + 0.02 * Math.sin(t * 0.0004 + p.t);
      if (Math.random() < 0.002) p.v = byte();
      ctx.fillStyle = "rgba(" + p.hue + "," + Math.max(a, 0) + ")";
      ctx.fillText(p.v, p.x, p.y);
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
