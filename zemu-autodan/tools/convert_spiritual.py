#!/usr/bin/env python3
"""convert_spiritual.py — 将 Spiritual-Spell-Red-Teaming 的 md 语料转换为结构化 JSON。
输出:resources/corpus.json (数组 [{name, model, category, prompt}])
提取规则:
- model:目录树第一级(Anthropic/ChatGPT/Gemini/Grok/Other LLMs/System Prompts/ENI-Tutor)
- name:文件名(去 .md)
- prompt:优先取 "Jailbreak Prompt:" 之后的 ```text 代码块;否则取全文
- 清理:去 Unicode 变体选择符/控制符、压缩空行
"""
import json, os, re, sys

ROOT = os.path.join(os.path.dirname(__file__), '..', 'Spiritual-Spell-Red-Teaming', 'Jailbreak-Guide')
OUT = os.path.join(os.path.dirname(__file__), '..', 'src', 'resources', 'corpus.json')

VS_RE = re.compile(r'[\U000FE000-\U000FE0FF\uE0000-\uE007F]')  # 变体选择符/tag 字符
CTRL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

def clean(s: str) -> str:
    s = VS_RE.sub('', s)
    s = CTRL_RE.sub('', s)
    s = s.replace('\u3000', ' ')  # 全角空格当空白
    # 压缩 3+ 连续空行为 2 行
    s = re.sub(r'\n{3,}', '\n\n', s)
    return s.strip()

def extract_prompt(text: str) -> str:
    # 优先 "Jailbreak Prompt:" 后的 ```text 块
    m = re.search(r'Jailbreak Prompt:\s*```(?:text)?\s*\n(.*?)```', text, re.S | re.I)
    if m:
        return clean(m.group(1))
    # 其次任意 ``` 代码块(取最长)
    blocks = re.findall(r'```(?:text)?\s*\n(.*?)```', text, re.S | re.I)
    if blocks:
        return clean(max(blocks, key=len))
    # 否则全文(去标题行)
    body = re.sub(r'^#.*$', '', text, flags=re.M)
    return clean(body)

def main():
    entries = []
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT)
        parts = [p for p in rel.split(os.sep) if p and p != '.']
        for fn in sorted(filenames):
            if not fn.endswith('.md'):
                continue
            if fn.upper() in ('README.MD', 'README.MD~') or fn.startswith('.'):
                skipped += 1
                continue
            path = os.path.join(dirpath, fn)
            try:
                text = open(path, encoding='utf-8', errors='replace').read()
            except Exception:
                skipped += 1
                continue
            prompt = extract_prompt(text)
            # 内容太短或空白噪音过多(视觉噪音填充)跳过
            nonws = re.sub(r'[\s]', '', prompt)
            if len(prompt) < 50 or len(nonws) < 100:
                skipped += 1
                continue
            model = parts[0] if parts else 'Other'
            sub = parts[1] if len(parts) > 1 else ''
            category = f"{model}/{sub}".strip('/')
            entries.append({
                'name': fn[:-3],
                'model': model,
                'category': category,
                'prompt': prompt,
            })
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=1)
    total_bytes = sum(len(e['prompt']) for e in entries)
    print(f"entries: {len(entries)}  skipped: {skipped}  total_prompt_bytes: {total_bytes/1024/1024:.1f} MB")
    from collections import Counter
    for model, n in Counter(e['model'] for e in entries).most_common():
        print(f"  {model:<16} {n}")

if __name__ == '__main__':
    sys.exit(main())
