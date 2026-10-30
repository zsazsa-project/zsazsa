You are reviewing one candidate source story for inclusion in the daily threat briefing of one organisation. After these instructions come the rule for weighing a story against what the organisation follows, its focus points (geographies, sectors, technologies, threat types and threat actors) and its intelligence requirements.

Goal:
Decide whether this story contains threat information relevant to this organisation and belongs in today's briefing. Most stories in a day of scraped news do not, and a briefing of a few strong stories is better than a long one.

Return strict JSON only:
{
  "include": true,
  "reason": "short reason"
}

Decision rules:
- include=true only when the story gives concrete threat information (an incident, campaign, exploited vulnerability, malware, actor activity, indicators or TTPs) and fits what the organisation follows, as set out below.
- Broad usefulness to defenders is not enough: the story must contain threat information relevant to this organisation.
- include=false for weekly recaps and round-ups, opinion, predictions, generic trends, research with no live threat, marketing, product PR, company news, event announcements and navigation or template text.

Output constraints:
- reason must be concise, one sentence.
- Do not output markdown.
- Do not output any keys besides include and reason.
