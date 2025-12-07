"use client";

import { useRef, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, MeshTransmissionMaterial } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import * as THREE from "three";

function ShieldGeometry() {
  const meshRef = useRef<THREE.Mesh>(null);
  const innerRef = useRef<THREE.Mesh>(null);
  const ringRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (!meshRef.current) return;
    const t = state.clock.elapsedTime;
    meshRef.current.rotation.y = Math.sin(t * 0.3) * 0.2;
    meshRef.current.rotation.x = Math.cos(t * 0.2) * 0.1;

    if (innerRef.current) {
      innerRef.current.rotation.z = t * 0.5;
    }
    if (ringRef.current) {
      ringRef.current.rotation.z = -t * 0.3;
    }
  });

  const accentColor = useMemo(() => new THREE.Color("#7c3aed"), []);
  const glowColor = useMemo(() => new THREE.Color("#a855f7"), []);

  return (
    <Float speed={2} rotationIntensity={0.3} floatIntensity={0.8}>
      <group ref={meshRef}>
        {/* Outer icosahedron - glass shell */}
        <mesh scale={1.4}>
          <icosahedronGeometry args={[1, 1]} />
          <MeshTransmissionMaterial
            backside
            samples={8}
            thickness={0.3}
            chromaticAberration={0.05}
            anisotropy={0.3}
            distortion={0.2}
            distortionScale={0.3}
            temporalDistortion={0.1}
            color="#e0d5f7"
            transmission={0.95}
            roughness={0.1}
          />
        </mesh>

        {/* Inner glowing core */}
        <mesh ref={innerRef} scale={0.6}>
          <octahedronGeometry args={[1, 0]} />
          <meshStandardMaterial
            color={accentColor}
            emissive={accentColor}
            emissiveIntensity={2}
            toneMapped={false}
          />
        </mesh>

        {/* Orbit ring */}
        <mesh ref={ringRef} scale={1.1}>
          <torusGeometry args={[1, 0.015, 16, 64]} />
          <meshStandardMaterial
            color={glowColor}
            emissive={glowColor}
            emissiveIntensity={1.5}
            toneMapped={false}
          />
        </mesh>

        {/* Second ring perpendicular */}
        <mesh ref={ringRef} rotation={[Math.PI / 2, 0, 0]} scale={1.0}>
          <torusGeometry args={[1, 0.01, 16, 64]} />
          <meshStandardMaterial
            color={glowColor}
            emissive={glowColor}
            emissiveIntensity={1}
            toneMapped={false}
          />
        </mesh>
      </group>
    </Float>
  );
}

export function Scene3D({ className = "" }: { className?: string }) {
  return (
    <div className={`${className}`}>
      <Canvas
        camera={{ position: [0, 0, 5], fov: 45 }}
        frameloop="always"
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
        style={{ background: "transparent" }}
      >
        <ambientLight intensity={0.3} />
        <directionalLight position={[5, 5, 5]} intensity={0.8} />
        <pointLight position={[-3, -3, 2]} intensity={0.5} color="#7c3aed" />
        <ShieldGeometry />
        <EffectComposer>
          <Bloom
            luminanceThreshold={0.8}
            intensity={0.6}
            levels={6}
            mipmapBlur
          />
        </EffectComposer>
      </Canvas>
    </div>
  );
}
