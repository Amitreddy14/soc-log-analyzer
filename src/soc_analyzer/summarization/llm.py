"""LLM-powered incident summarizer.

Uses OpenAI, Anthropic, or local Ollama to generate natural language
incident reports. Falls back to template-based summarization if the
LLM call fails for any reason.

Ollama support enables fully local, offline, zero-cost summarization
using models like llama3, mistral, phi3, or qwen2.
"""

from __future__ import annotations

import json
import os
from typing import Any

from soc_analyzer.correlation.incidents import Incident
from soc_analyzer.summarization.prompts import build_prompt, parse_llm_response
from soc_analyzer.summarization.report import IncidentReport, IoC, ResponseAction
from soc_analyzer.summarization.template import TemplateSummarizer
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)


class LLMSummarizer:
    """LLM-powered incident summarizer with template fallback.

    Supports:
        - Ollama (local — llama3, mistral, phi3, qwen2, gemma2)
        - OpenAI (gpt-4o, gpt-4o-mini)
        - Anthropic (claude-3-sonnet, claude-3-haiku)

    Usage:
        summarizer = LLMSummarizer(provider="ollama", model="llama3")
        report = summarizer.summarize(incident)
    """

    def __init__(
        self,
        provider: str = "ollama",
        model: str | None = None,
        api_key: str | None = None,
        ollama_base_url: str = "http://localhost:11434",
    ) -> None:
        self.provider = provider.lower()
        self.api_key = api_key or self._get_api_key()
        self.model = model or self._default_model()
        self.ollama_base_url = ollama_base_url
        self._template_fallback = TemplateSummarizer()

    def _get_api_key(self) -> str | None:
        """Get API key from environment. Ollama doesn't need one."""
        if self.provider == "ollama":
            return "not-needed"
        elif self.provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif self.provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY")
        return os.getenv("LLM_API_KEY")

    def _default_model(self) -> str:
        """Default model for each provider."""
        defaults = {
            "ollama": "llama3",
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-haiku-20240307",
        }
        return defaults.get(self.provider, "llama3")

    def summarize(self, incident: Incident) -> IncidentReport:
        """Generate an incident report using the LLM.

        Falls back to template-based summarization on any failure.
        """
        if self.provider != "ollama" and not self.api_key:
            logger.warning("no_api_key", provider=self.provider)
            return self._template_fallback.summarize(incident)

        try:
            system_prompt, user_prompt = build_prompt(incident)
            response_text = self._call_llm(system_prompt, user_prompt)
            parsed = parse_llm_response(response_text)

            if "error" in parsed:
                logger.warning("llm_parse_failed", error=parsed["error"])
                return self._template_fallback.summarize(incident)

            report = self._build_report_from_llm(incident, parsed)
            logger.info("llm_summarized", incident_id=incident.id, model=self.model)
            return report

        except Exception as e:
            logger.error("llm_summarization_failed", error=str(e))
            return self._template_fallback.summarize(incident)

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call the LLM API. Returns the raw response text."""
        if self.provider == "ollama":
            return self._call_ollama(system_prompt, user_prompt)
        elif self.provider == "openai":
            return self._call_openai(system_prompt, user_prompt)
        elif self.provider == "anthropic":
            return self._call_anthropic(system_prompt, user_prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """Call local Ollama API.

        Ollama exposes an OpenAI-compatible endpoint at /api/chat.
        No API key needed — runs entirely on your machine.
        """
        import httpx

        response = httpx.post(
            f"{self.ollama_base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.3,
                    "num_predict": 2000,
                },
            },
            timeout=120.0,  # Local models can be slower
        )
        response.raise_for_status()
        data = response.json()
        return data["message"]["content"]

    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        """Call OpenAI API."""
        import httpx

        response = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 2000,
                "response_format": {"type": "json_object"},
            },
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_anthropic(self, system_prompt: str, user_prompt: str) -> str:
        """Call Anthropic API."""
        import httpx

        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.3,
                "max_tokens": 2000,
            },
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return data["content"][0]["text"]

    def _build_report_from_llm(
        self, incident: Incident, parsed: dict[str, Any]
    ) -> IncidentReport:
        """Build an IncidentReport from parsed LLM output."""
        iocs = []
        for ioc_data in parsed.get("iocs", []):
            try:
                iocs.append(IoC(
                    type=ioc_data.get("type", "unknown"),
                    value=str(ioc_data.get("value", "")),
                    context=ioc_data.get("context", ""),
                    action=ioc_data.get("action", "investigate"),
                ))
            except Exception:
                continue

        actions = []
        for action_data in parsed.get("response_actions", []):
            try:
                actions.append(ResponseAction(
                    priority=int(action_data.get("priority", 3)),
                    action=action_data.get("action", ""),
                    rationale=action_data.get("rationale", ""),
                ))
            except Exception:
                continue

        return IncidentReport(
            incident_id=incident.id,
            generator=f"llm:{self.provider}/{self.model}",
            severity=incident.severity.value,
            title=incident.title or incident.generate_title(),
            event_count=incident.event_count,
            duration_seconds=incident.duration_seconds,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            executive_summary=parsed.get("executive_summary", ""),
            timeline_narrative=parsed.get("timeline_narrative", ""),
            impact_assessment=parsed.get("impact_assessment", ""),
            technical_details=parsed.get("technical_details", ""),
            iocs=iocs,
            response_actions=actions,
            mitre_techniques=parsed.get("mitre_techniques", []),
            attack_stages=incident.attack_stages,
            affected_assets=list(incident.destination_ips),
        )
