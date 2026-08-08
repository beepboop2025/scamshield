"""Fresh, corroborated USDT/INR reference rates.

The detector's original ``MARKET_USDT_INR`` constant is a safe offline test
fixture, not a production price oracle.  This module queries two independent
public endpoints, validates their shapes and bounds, and publishes the median
only when they agree.  If they disagree, the higher rate is used
conservatively: a higher baseline makes an above-market detector less likely to
false-positive.
"""

from __future__ import annotations

import json
import math
import os
import statistics
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, Sequence
from urllib.parse import urlsplit

from .detector import MARKET_USDT_INR

MAX_RESPONSE_BYTES = 64 * 1024
MIN_PLAUSIBLE_RATE = 40.0
MAX_PLAUSIBLE_RATE = 250.0


class RateProviderError(RuntimeError):
    pass


def _utc_iso(epoch: float | None = None) -> str:
    value = time.time() if epoch is None else epoch
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def _finite_rate(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise RateProviderError(f"{field} is boolean, not a rate")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RateProviderError(f"{field} is not numeric") from exc
    if not math.isfinite(number):
        raise RateProviderError(f"{field} is not finite")
    if not MIN_PLAUSIBLE_RATE <= number <= MAX_PLAUSIBLE_RATE:
        raise RateProviderError(f"{field}={number} is outside the defensive INR bound")
    return number


def _reject_constant(value: str) -> None:
    raise RateProviderError(f"non-finite JSON value {value!r}")


def _fetch_json(url: str, *, headers: dict[str, str] | None = None,
                timeout: float = 5.0) -> Any:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RateProviderError("rate endpoint must be an https URL without credentials")
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "ScamShield-rate-oracle/1.0",
    }
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final = urlsplit(response.geturl())
            if (
                final.scheme != "https"
                or final.hostname != parsed.hostname
                or final.port != parsed.port
                or final.username
                or final.password
            ):
                raise RateProviderError(
                    "rate endpoint redirected outside its original HTTPS origin"
                )
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    if int(content_length) > MAX_RESPONSE_BYTES:
                        raise RateProviderError("rate response exceeds the byte limit")
                except ValueError as exc:
                    raise RateProviderError("invalid Content-Length from rate provider") from exc
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except RateProviderError:
        raise
    except Exception as exc:
        raise RateProviderError(f"rate request failed: {exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RateProviderError("rate response exceeds the byte limit")
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RateProviderError(f"rate response is not strict UTF-8 JSON: {exc}") from exc


@dataclass(frozen=True)
class RateObservation:
    provider: str
    rate: float
    observed_at: str
    source_url: str


class RateProvider(Protocol):
    name: str

    def fetch(self) -> RateObservation:
        ...


class CoinbaseRateProvider:
    name = "coinbase"
    url = "https://api.coinbase.com/v2/exchange-rates?currency=USDT"

    def __init__(self, *, fetch_json: Callable[..., Any] = _fetch_json):
        self._fetch_json = fetch_json

    def fetch(self) -> RateObservation:
        payload = self._fetch_json(self.url)
        try:
            data = payload["data"]
            if data["currency"] != "USDT":
                raise RateProviderError("Coinbase returned a different base currency")
            rate = _finite_rate(data["rates"]["INR"], "Coinbase USDT/INR")
        except (KeyError, TypeError) as exc:
            raise RateProviderError("Coinbase response shape changed") from exc
        return RateObservation(
            provider=self.name,
            rate=rate,
            observed_at=_utc_iso(),
            source_url=self.url,
        )


class CoinGeckoRateProvider:
    name = "coingecko"
    url = (
        "https://api.coingecko.com/api/v3/simple/price"
        "?ids=tether&vs_currencies=inr&include_last_updated_at=true"
    )

    def __init__(self, *, fetch_json: Callable[..., Any] = _fetch_json,
                 api_key: str | None = None):
        self._fetch_json = fetch_json
        self._api_key = api_key if api_key is not None else os.environ.get(
            "COINGECKO_DEMO_API_KEY", ""
        )

    def fetch(self) -> RateObservation:
        headers = {"x-cg-demo-api-key": self._api_key} if self._api_key else {}
        payload = self._fetch_json(self.url, headers=headers)
        try:
            tether = payload["tether"]
            rate = _finite_rate(tether["inr"], "CoinGecko USDT/INR")
            updated = tether.get("last_updated_at")
        except (KeyError, TypeError) as exc:
            raise RateProviderError("CoinGecko response shape changed") from exc
        observed_at = _utc_iso()
        if isinstance(updated, (int, float)) and not isinstance(updated, bool):
            now = time.time()
            if math.isfinite(float(updated)) and 0 < float(updated) <= now + 300:
                observed_at = _utc_iso(float(updated))
        return RateObservation(
            provider=self.name,
            rate=rate,
            observed_at=observed_at,
            source_url=self.url,
        )


@dataclass(frozen=True)
class RateQuote:
    rate: float
    status: str
    observed_at: str
    sources: tuple[str, ...]
    source_urls: tuple[str, ...]
    spread_pct: float | None
    warnings: tuple[str, ...] = ()

    @property
    def numeric_detection_allowed(self) -> bool:
        """Fallback is documentation, not evidence for a live numeric anomaly."""
        return self.status != "FALLBACK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rate": round(self.rate, 4),
            "status": self.status,
            "observed_at": self.observed_at,
            "sources": list(self.sources),
            "source_urls": list(self.source_urls),
            "spread_pct": (
                None if self.spread_pct is None else round(self.spread_pct, 6)
            ),
            "warnings": list(self.warnings),
        }


class MarketRateOracle:
    """Thread-safe, TTL-cached multi-source rate oracle."""

    def __init__(
        self,
        providers: Sequence[RateProvider] | None = None,
        *,
        fallback_rate: float = MARKET_USDT_INR,
        ttl_seconds: float = 15 * 60,
        max_stale_seconds: float = 24 * 60 * 60,
        max_spread_pct: float = 0.05,
        clock: Callable[[], float] = time.time,
    ):
        self.providers = tuple(providers or (
            CoinbaseRateProvider(), CoinGeckoRateProvider(),
        ))
        if not self.providers:
            raise ValueError("at least one rate provider is required")
        self.fallback_rate = _finite_rate(fallback_rate, "fallback rate")
        if ttl_seconds <= 0 or max_stale_seconds < ttl_seconds:
            raise ValueError("rate TTLs are inconsistent")
        if not 0 < max_spread_pct <= 0.5:
            raise ValueError("max_spread_pct must be in (0, 0.5]")
        self.ttl_seconds = ttl_seconds
        self.max_stale_seconds = max_stale_seconds
        self.max_spread_pct = max_spread_pct
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: RateQuote | None = None
        self._cache_time = 0.0

    def quote(self, *, force_refresh: bool = False) -> RateQuote:
        now = self._clock()
        with self._lock:
            if (
                not force_refresh
                and self._cache is not None
                and now - self._cache_time < self.ttl_seconds
            ):
                return self._cache

            observations, failures = self._collect()
            if observations:
                quote = self._fuse(observations, failures)
                self._cache = quote
                self._cache_time = now
                return quote

            if self._cache is not None and now - self._cache_time <= self.max_stale_seconds:
                warnings = tuple(dict.fromkeys(
                    self._cache.warnings
                    + ("all live providers failed; using the last successful quote",)
                    + tuple(failures)
                ))
                return replace(self._cache, status="STALE", warnings=warnings)

            return RateQuote(
                rate=self.fallback_rate,
                status="FALLBACK",
                observed_at=_utc_iso(now),
                sources=("static-detector-fallback",),
                source_urls=(),
                spread_pct=None,
                warnings=tuple(failures) + (
                    "no live reference rate; numeric rate detection is disabled",
                ),
            )

    def _collect(self) -> tuple[list[RateObservation], list[str]]:
        observations: list[RateObservation] = []
        failures: list[str] = []
        with ThreadPoolExecutor(max_workers=min(4, len(self.providers))) as pool:
            futures = {pool.submit(provider.fetch): provider for provider in self.providers}
            for future in as_completed(futures):
                provider = futures[future]
                try:
                    result = future.result()
                    if result.provider != provider.name:
                        raise RateProviderError("provider identity mismatch")
                    _finite_rate(result.rate, f"{provider.name} rate")
                    observations.append(result)
                except Exception as exc:
                    failures.append(f"{provider.name}: {exc}")
        observations.sort(key=lambda item: item.provider)
        failures.sort()
        return observations, failures

    def _fuse(self, observations: Sequence[RateObservation],
              failures: Sequence[str]) -> RateQuote:
        rates = [item.rate for item in observations]
        median = float(statistics.median(rates))
        spread = 0.0 if len(rates) == 1 else (max(rates) - min(rates)) / median
        warnings = list(failures)
        if len(observations) == 1:
            status = "SINGLE_SOURCE"
            rate = rates[0]
            warnings.append("only one live market-rate source was available")
        elif spread <= self.max_spread_pct:
            status = "CORROBORATED"
            rate = median
        else:
            status = "DIVERGENT"
            # Conservative for a scam detector: this raises the anomaly bar.
            rate = max(rates)
            warnings.append(
                "live sources diverged beyond the configured tolerance; "
                "using the higher rate to reduce false positives"
            )
        return RateQuote(
            rate=rate,
            status=status,
            observed_at=max(item.observed_at for item in observations),
            sources=tuple(item.provider for item in observations),
            source_urls=tuple(item.source_url for item in observations),
            spread_pct=spread,
            warnings=tuple(warnings),
        )
