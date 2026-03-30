"""SIEMForge Sigma-to-SIEM query converters."""
from converters.splunk import SplunkConverter
from converters.elastic import ElasticConverter
from converters.kibana import KibanaConverter

BACKENDS: dict = {
    "splunk": SplunkConverter,
    "elastic": ElasticConverter,
    "kibana": KibanaConverter,
}
