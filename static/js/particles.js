(() => {
  const canvas = document.getElementById('particle-field');
  if (!canvas) return;

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const mobile = window.matchMedia('(max-width: 980px)');
  if (reduceMotion.matches || mobile.matches) {
    canvas.remove();
    return;
  }

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  const pointer = { x: -9999, y: -9999 };
  const particles = [];
  let width = 0;
  let height = 0;
  let raf = 0;

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const count = Math.min(72, Math.max(34, Math.floor((width * height) / 28000)));
    particles.length = 0;
    for (let i = 0; i < count; i += 1) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.16,
        vy: (Math.random() - 0.5) * 0.16,
        r: Math.random() * 1.6 + 0.35,
        a: Math.random() * 0.35 + 0.12,
      });
    }
  };

  const draw = () => {
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = '#B11226';
    particles.forEach((p, index) => {
      const dx = p.x - pointer.x;
      const dy = p.y - pointer.y;
      const dist = Math.hypot(dx, dy);
      if (dist < 130) {
        const force = (130 - dist) / 130;
        p.x += (dx / Math.max(dist, 1)) * force * 0.8;
        p.y += (dy / Math.max(dist, 1)) * force * 0.8;
      }

      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -10) p.x = width + 10;
      if (p.x > width + 10) p.x = -10;
      if (p.y < -10) p.y = height + 10;
      if (p.y > height + 10) p.y = -10;

      ctx.globalAlpha = p.a;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();

      for (let j = index + 1; j < particles.length; j += 1) {
        const other = particles[j];
        const gap = Math.hypot(p.x - other.x, p.y - other.y);
        if (gap < 118) {
          ctx.globalAlpha = (1 - gap / 118) * 0.08;
          ctx.strokeStyle = '#A30015';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(other.x, other.y);
          ctx.stroke();
        }
      }
    });
    ctx.globalAlpha = 1;
    raf = window.requestAnimationFrame(draw);
  };

  window.addEventListener('resize', resize, { passive: true });
  window.addEventListener('pointermove', (event) => {
    pointer.x = event.clientX;
    pointer.y = event.clientY;
  }, { passive: true });
  window.addEventListener('pointerleave', () => {
    pointer.x = -9999;
    pointer.y = -9999;
  }, { passive: true });

  resize();
  draw();

  window.addEventListener('pagehide', () => window.cancelAnimationFrame(raf), { once: true });
})();
