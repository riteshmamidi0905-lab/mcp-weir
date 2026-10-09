#!/usr/bin/env python3
"""Market-research method for docs/design/01-market-research.md.
INPUT NOT INCLUDED: the postings are third-party content from public employer job-board APIs (Greenhouse, Lever, Ashby, Workday),
fetched 2026-10-02..08. Only aggregate counts are published. Paths below point at the author's local copy.
Keyword prevalence is a coarse signal (regex over free text), not a labelled study."""
import json, os, re, collections
RAW = os.environ.get("POSTINGS_DIR", "postings/").rstrip("/") + "/"
rows, seen = [], set()
for fn in ["all2.jsonl", "wd1.jsonl", "wd2.jsonl", "wd3.jsonl"]:
    for line in open(RAW+fn):
        try: j = json.loads(line)
        except Exception: continue
        k = j.get("url") or (j.get("slug"), j.get("id"))
        if k in seen: continue
        seen.add(k); rows.append(j)
T_AI  = re.compile(r"\b(ai|ml|llm|genai|generative|agent(ic|s)?|applied (ai|ml|scientist)|forward[- ]deployed|fde|deployment strategist)\b", re.I)
T_ENG = re.compile(r"engineer|developer|architect|forward[- ]deployed|deployment strategist|solutions", re.I)
T_BAD = re.compile(r"\b(sales|account executive|recruit|marketing|counsel|attorney|legal|nurse|trainer|freelance|hardware|mechanical|electrical|civil|manufactur|intern)\b", re.I)
BODY  = re.compile(r"\b(llm|large language model|generative ai|genai|agentic|ai agents?|rag|retrieval[- ]augmented)\b", re.I)
def recent(j):
    p = (j.get("posted") or "")[:10]
    return p >= "2026-06-01"
coh = [j for j in rows if T_AI.search(j["title"]) and T_ENG.search(j["title"]) and not T_BAD.search(j["title"]) and BODY.search(j["title"]+" "+j.get("desc","")) and recent(j)]
fde = [j for j in coh if re.search(r"forward[- ]deployed|fde|deployment strategist|solutions? (engineer|architect)", j["title"], re.I)]
app = [j for j in coh if re.search(r"applied|ai engineer|llm|genai|generative|agent|ai/ml", j["title"], re.I) and j not in fde]
print("recent (posted >= 2026-06-01) AI-engineering cohort:", len(coh), "| applied-AI/AI-engineer titles:", len(app), "| FDE/solutions titles:", len(fde), "| companies:", len({j['slug'] for j in coh}))
CAPS = [
 ("evaluation (specific: evals, LLM-as-judge, eval suite/dataset/golden set)", r"\bevals?\b|llm[- ]as[- ]a?[- ]judge|eval(uation)? (framework|harness|suite|pipeline|set|dataset|metric)|golden (set|dataset)|ground[- ]truth|benchmark"),
 ("MCP (Model Context Protocol)", r"\bmcp\b|model context protocol"),
 ("tool / function calling", r"tool[- ]?(use|calling|call)s?\b|function[- ]calling|tool integration"),
 ("agent security (guardrails, prompt injection, red-team, exfiltration, least privilege)", r"guardrail|prompt[- ]injection|jailbreak|red[- ]team|ai safety|agent security|exfiltrat|least[- ]privilege|llama guard|nemo guardrails|trust and safety"),
 ("human-in-the-loop / approval / oversight", r"human[- ]in[- ]the[- ]loop|hitl|human (review|oversight|approval)|approval workflow"),
 ("observability (tracing, Langfuse/LangSmith/OTel)", r"tracing|langsmith|langfuse|opentelemetry|\botel\b|arize|phoenix|helicone|observability"),
 ("orchestration / multi-agent / workflows", r"multi[- ]agent|orchestrat|langgraph|crewai|autogen|temporal|durable|workflow automation"),
 ("RAG / vector search", r"\brag\b|retrieval[- ]augmented|vector (database|db|store|search)|pinecone|weaviate|pgvector|chroma|faiss|embeddings?"),
 ("enterprise integration (APIs, OAuth/SSO, SaaS connectors)", r"oauth|\bsso\b|saml|salesforce|servicenow|zendesk|jira|netsuite|hubspot|rest api|webhook|connector|integrations?\b"),
 ("computer use / browser agents", r"computer[- ]use|browser (agent|automation|use)|playwright|selenium|web agents?|gui agent"),
 ("text-to-SQL / data agents", r"text[- ]to[- ]sql|nl2sql|natural language to sql|data agents?|analytics agents?|semantic layer"),
 ("voice / speech agents", r"voice (agent|ai|assistant)|speech|text[- ]to[- ]speech|\basr\b|webrtc|telephony"),
 ("agent memory / long-running state", r"agent memory|long[- ]term memory|long[- ]running|durable execution|checkpoint"),
 ("sandboxing / isolated code execution", r"sandbox|code execution|code interpreter|isolated environment"),
 ("fine-tuning / post-training", r"fine[- ]?tun|\blora\b|rlhf|post-?training|\bsft\b"),
 ("inference / serving / latency", r"inference|vllm|tensorrt|model serving|quantiz|\blatency\b"),
 ("cloud platform (AWS/GCP/Azure)", r"\baws\b|\bgcp\b|google cloud|azure|bedrock|vertex|sagemaker"),
 ("customer-facing / deployment into customer environments", r"customer[- ]facing|forward[- ]deployed|client[- ]facing|customer environment|on-?site|deploy(ing)? (to|with|for) customers?"),
]
def pct(js, rx):
    r = re.compile(rx, re.I); k = sum(1 for j in js if r.search(j["title"]+" "+j.get("desc","")))
    return k, 100*k/max(1,len(js))
print("\n%-86s %-16s %-16s %-16s" % ("capability", "all (n=%d)" % len(coh), "applied-AI (n=%d)" % len(app), "FDE/sol. (n=%d)" % len(fde)))
out = {}
for name, rx in CAPS:
    a, b, c = pct(coh, rx), pct(app, rx), pct(fde, rx)
    out[name] = {"all": a, "applied": b, "fde": c}
    print("%-86s %-16s %-16s %-16s" % (name, "%d (%.0f%%)" % (a[0], a[1]), "%d (%.0f%%)" % (b[0], b[1]), "%d (%.0f%%)" % (c[0], c[1])))
# co-occurrence: postings that mention (MCP or tool calling) AND agent-security terms
r1 = re.compile(CAPS[1][1]+"|"+CAPS[2][1], re.I); r2 = re.compile(CAPS[3][1], re.I)
both = sum(1 for j in coh if r1.search(j["title"]+" "+j.get("desc","")) and r2.search(j["title"]+" "+j.get("desc","")))
print("\nmention (MCP or tool calling) AND (agent security terms):", both, "of", len(coh))
json.dump({"n": len(coh), "applied": len(app), "fde": len(fde), "companies": len({j['slug'] for j in coh}), "caps": out}, open("market_mine.json", "w"), indent=1)
