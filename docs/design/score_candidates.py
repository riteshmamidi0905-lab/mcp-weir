#!/usr/bin/env python3
"""M3 candidate scoring. Scores are the author's judgement (1-5, higher is better for every column, including
'low overlap' and 'low gimmick risk'); the script only does the arithmetic and shows sensitivity to the weights.
NV means novelty relative to this portfolio AND the field: the information-flow idea is established (CaMeL, FIDES), so Weir gets 3, not 5."""
DIMS = ["TD","NV","US","DM","AA","FD","AE","EV","FN","OV","GR"]
NAMES = {"TD":"technical depth","NV":"novelty","US":"real usefulness","DM":"demo impact","AA":"Applied AI relevance","FD":"FDE relevance",
         "AE":"AI Engineer relevance","EV":"evaluation potential","FN":"finishable credible V1","OV":"low overlap with portfolio","GR":"low gimmick risk"}
C = {
 "C1 Weir (information-flow gateway at the MCP boundary)":       [5,3,4,4,4,4,5,5,4,4,3],
 "C2 Browser agent with verified actions":                        [4,3,3,5,3,3,4,3,2,5,2],
 "C3 Durable agent workflow engine (chaos-tested)":               [4,2,4,2,3,3,4,4,3,2,3],
 "C4 Governed data-analyst agent (NL-to-SQL + number verification)":[3,2,5,4,5,5,3,4,4,3,3],
 "C5 Schema-constrained decoding study on the Copilot failures":  [3,2,4,2,3,2,4,5,5,3,3],
 "C6 Agent trace record / replay / diff (observability)":         [3,2,4,3,3,2,4,3,4,3,2],
 "C7 Real-time voice agent":                                      [4,3,3,5,3,3,4,3,1,5,3],
 "C8 Agent long-term memory with temporal updates":               [3,3,4,3,4,3,4,4,3,3,3],
}
W = {
 "balanced (chosen)":        dict(TD=1.5,NV=.75,US=1,DM=1,AA=1,FD=.75,AE=1.25,EV=1.5,FN=1.5,OV=1,GR=1),
 "equal":                    {d:1 for d in DIMS},
 "career-fit heavy (AA,FD,AE x2)": dict(TD=1,NV=.5,US=1,DM=1,AA=2,FD=2,AE=2,EV=1,FN=1,OV=1,GR=1),
 "finishability heavy (FN x3)":    dict(TD=1,NV=.5,US=1,DM=1,AA=1,FD=1,AE=1,EV=1,FN=3,OV=1,GR=1),
}
def tot(sc, w): return 100*sum(s*w[d] for s,d in zip(sc,DIMS))/(5*sum(w.values()))
print("| Candidate | " + " | ".join(DIMS) + " |"); print("|---|" + "---|"*len(DIMS))
for n,sc in C.items(): print(f"| {n} | " + " | ".join(map(str,sc)) + " |")
print()
print("| Candidate | " + " | ".join(W) + " |"); print("|---|" + "---|"*len(W))
for n,sc in sorted(C.items(), key=lambda kv:-tot(kv[1],W["balanced (chosen)"])):
    print(f"| {n} | " + " | ".join(f"{tot(sc,w):.0f}" for w in W.values()) + " |")
print()
for k,w in W.items():
    r = sorted(C, key=lambda n:-tot(C[n],w)); print(k, "->", [x.split()[0] for x in r[:3]])
print("\ncolumns:", {d:NAMES[d] for d in DIMS})
