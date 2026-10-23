// Isolated decorative React island: no application data or layout changes.
import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { MeshGradient } from '@paper-design/shaders-react';

const card = document.querySelector('.next-action-card');
const reduced = matchMedia('(prefers-reduced-motion: reduce)');
function Background() {
  const [running, setRunning] = useState(!document.hidden && !reduced.matches);
  useEffect(() => {
    let onscreen = true;
    const update = () => setRunning(onscreen && !document.hidden && !reduced.matches);
    const observer = new IntersectionObserver(([entry]) => { onscreen = entry.isIntersecting; update(); });
    observer.observe(card);
    document.addEventListener('visibilitychange', update);
    reduced.addEventListener('change', update);
    return () => { observer.disconnect(); document.removeEventListener('visibilitychange', update); reduced.removeEventListener('change', update); };
  }, []);
  return <MeshGradient style={{ width: '100%', height: '100%' }}
    colors={['#e0eaff', '#241d9a', '#f75092', '#9f50d3']}
    distortion={0.8} swirl={0.1} grainMixer={0} grainOverlay={0}
    speed={running ? 1 : 0} maxPixelCount={700000} minPixelRatio={1} />;
}
// Without WebGL2, retain the original card background unchanged.
if (card) {
  const probe = document.createElement('canvas');
  const gl = probe.getContext('webgl2');
  if (gl) {
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    const layer = document.createElement('div');
    layer.className = 'action-shader';
    layer.setAttribute('aria-hidden', 'true');
    card.prepend(layer);
    createRoot(layer).render(<Background />);
  }
}
