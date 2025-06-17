import { useEffect, useState } from "react";
import { Routes, Route } from "react-router-dom";

export default function View() {
  return (
    <Routes>
      <Route path="/" element={<SolarSystem />} />
    </Routes>
  );
}

function SolarSystem() {
  const [stars, setStars] = useState([]);
  
  useEffect(() => {
    // Generate stars
    const newStars = [];
    for (let i = 0; i < 100; i++) {
      newStars.push({
        id: i,
        x: Math.random() * 100,
        y: Math.random() * 100,
        size: Math.random() * 2 + 1,
        opacity: Math.random() * 0.7 + 0.3
      });
    }
    setStars(newStars);
    
    // Enhanced twinkle effect with more intensity
    const twinkleInterval = setInterval(() => {
      setStars(prevStars => 
        prevStars.map(star => ({
          ...star,
          opacity: Math.max(0.2, Math.min(1, star.opacity + (Math.random() - 0.5) * 0.3)),
          size: Math.max(0.8, Math.min(3, star.size + (Math.random() - 0.5) * 0.2))
        }))
      );
    }, 300);
    
    return () => clearInterval(twinkleInterval);
  }, []);
  
  return (
    <div style={{ 
      position: 'fixed', 
      top: 0, 
      left: 0, 
      width: '100vw', 
      height: '100vh', 
      overflow: 'hidden', 
      backgroundColor: '#000' 
    }}>
      {stars.map(star => (
        <div
          key={star.id}
          style={{
            position: 'absolute',
            left: `\${star.x}%`,
            top: `\${star.y}%`,
            width: `\${star.size}px`,
            height: `\${star.size}px`,
            backgroundColor: '#fff',
            borderRadius: '50%',
            opacity: star.opacity,
            transition: 'opacity 1s ease'
          }}
        />
      ))}
      
      <div style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        color: 'white',
        textAlign: 'center',
        zIndex: 1
      }}>
        <p>This is an empty view.</p>
      </div>
    </div>
  );
}