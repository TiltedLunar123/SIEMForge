"""SIEMForge Sigma-to-SIEM query converters."""
from .elastic import ElasticConverter
from .kibana import KibanaConverter
from .splunk import SplunkConverter

__all__ = ["SplunkConverter", "ElasticConverter", "KibanaConverter", "BACKENDS"]

BACKENDS: dict = {
    "splunk": SplunkConverter,
    "elastic": ElasticConverter,
    "kibana": KibanaConverter,
}
