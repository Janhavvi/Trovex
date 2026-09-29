import { useState } from 'react';
import { attackChains, type AttackChain } from '../data/mockData';

const nodeColors = {
  actor: { bg: '#1a0d20', border: '#ff3b3b', text: '#ff3b3b' },
  entry: { bg: '#1a1200', border: '#ffc107', text: '#ffc107' },
  pivot: { bg: '#0d1a20', border: '#00d4ff', text: '#00d4ff' },
  impact: { bg: '#200d0d', border: '#ff6b2b', text: '#ff6b2b' },
};

function ChainGraph({ chain }: { chain: AttackChain }) {
  const nodeWidth = 130;
  const nodeHeight = 54;
  const cols = chain.nodes.length;
  const svgWidth = Math.max(cols * (nodeWidth + 60), 500);
  const svgHeight = 200;
  const nodeY = (svgHeight - nodeHeight) / 2;

  const nodePositions: Record<string, { x: number; y: number }> = {};
  chain.nodes.forEach((node, i) => {
    nodePositions[node.id] = {
      x: 30 + i * ((svgWidth - 60 - nodeWidth) / Math.max(cols - 1, 1)),
      y: nodeY,
    };
  });

  return (
    <div style={{ overflowX: 'auto', padding: '8px 0' }}>
      <svg width={svgWidth} height={svgHeight} style={{ minWidth: svgWidth }}>
        {/* Edges */}
        {chain.edges.map((edge, i) => {
          const src = nodePositions[edge.source];
          const dst = nodePositions[edge.target];
          if (!src || !dst) return null;
          const x1 = src.x + nodeWidth;
          const y1 = src.y + nodeHeight / 2;
          const x2 = dst.x;
          const y2 = dst.y + nodeHeight / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={i}>
              <path
                d={`M ${x1} ${y1} C ${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`}
                fill="none" stroke="#1e2f46" strokeWidth="1.5"
                strokeDasharray="4 3"
              />
              {/* Arrow */}
              <polygon
                points={`${x2},${y2} ${x2 - 8},${y2 - 4} ${x2 - 8},${y2 + 4}`}
                fill="#1e2f46"
              />
              <text x={mx} y={Math.min(y1, y2) - 8} textAnchor="middle" fill="#3d5470"
                fontSize="8" fontFamily="JetBrains Mono, monospace">
                {edge.label}
              </text>
            </g>
          );
        })}

        {/* Nodes */}
        {chain.nodes.map(node => {
          const pos = nodePositions[node.id];
          const c = nodeColors[node.type];
          return (
            <g key={node.id}>
              <rect
                x={pos.x} y={pos.y} width={nodeWidth} height={nodeHeight}
                rx={6} fill={c.bg} stroke={c.border} strokeWidth="1"
                style={{ filter: `drop-shadow(0 0 4px ${c.border}44)` }}
              />
              <text x={pos.x + nodeWidth / 2} y={pos.y + 20} textAnchor="middle"
                fill={c.text} fontSize="10" fontFamily="JetBrains Mono, monospace" fontWeight="600">
                {node.label.split('\n')[0]}
              </text>
              {node.label.split('\n')[1] && (
                <text x={pos.x + nodeWidth / 2} y={pos.y + 33} textAnchor="middle"
                  fill={c.text + '99'} fontSize="9" fontFamily="JetBrains Mono, monospace">
                  {node.label.split('\n')[1]}
                </text>
              )}
              <text x={pos.x + nodeWidth / 2} y={pos.y + 47} textAnchor="middle"
                fill="#3d5470" fontSize="7.5" fontFamily="JetBrains Mono, monospace">
                {node.type.toUpperCase()}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default function AttackPaths() {
  const [activeChain, setActiveChain] = useState<AttackChain>(attackChains[0]);

  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 4 }}>
          {attackChains.length} attack chains validated
        </div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#e2eaf6' }}>Attack Path Analysis</h1>
      </div>

      {/* Chain selector */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        {attackChains.map(chain => (
          <button
            key={chain.id}
            onClick={() => setActiveChain(chain)}
            style={{
              padding: '8px 14px', borderRadius: 6, cursor: 'pointer',
              fontFamily: 'JetBrains Mono, monospace', fontSize: 10,
              background: activeChain.id === chain.id ? 'rgba(255,59,59,0.12)' : 'rgba(255,59,59,0.04)',
              border: `1px solid ${activeChain.id === chain.id ? '#ff3b3b66' : '#1e2f46'}`,
              color: activeChain.id === chain.id ? '#ff3b3b' : '#6b8aac',
              textAlign: 'left',
            }}
          >
            <div style={{ fontSize: 9, color: '#3d5470', marginBottom: 2 }}>{chain.id} · {chain.severity}</div>
            <div style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{chain.title}</div>
          </button>
        ))}
      </div>

      {/* Graph */}
      <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 8 }}>
          {activeChain.id} · ATTACK PATH GRAPH
        </div>
        <ChainGraph chain={activeChain} />

        {/* Node type legend */}
        <div style={{ display: 'flex', gap: 12, marginTop: 12, paddingTop: 12, borderTop: '1px solid #1e2f46' }}>
          {Object.entries(nodeColors).map(([type, c]) => (
            <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 10, height: 10, borderRadius: 2, background: c.bg, border: `1px solid ${c.border}` }} />
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 8, color: '#3d5470', textTransform: 'uppercase' }}>{type}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Narrative */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div style={{ background: '#0d1520', border: '1px solid #1e2f46', borderRadius: 8, padding: 16 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#3d5470', letterSpacing: 1, marginBottom: 8 }}>ATTACK NARRATIVE</div>
          <div style={{ fontSize: 12, color: '#a0b8d4', lineHeight: 1.7 }}>{activeChain.narrative}</div>
        </div>
        <div style={{ background: '#0d1520', border: '1px solid #ff3b3b22', borderRadius: 8, padding: 16 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#ff3b3b', letterSpacing: 1, marginBottom: 8 }}>BUSINESS IMPACT</div>
          <div style={{ fontSize: 12, color: '#a0b8d4', lineHeight: 1.7 }}>{activeChain.business_impact}</div>
        </div>
      </div>
    </div>
  );
}
