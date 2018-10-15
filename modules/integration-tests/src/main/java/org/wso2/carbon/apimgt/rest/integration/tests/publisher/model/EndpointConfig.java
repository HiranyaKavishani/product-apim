/*
 * WSO2 API Manager - Publisher API
 * This specifies a **RESTful API** for WSO2 **API Manager** - Publisher.  Please see [full swagger definition](https://raw.githubusercontent.com/wso2/carbon-apimgt/v6.0.4/components/apimgt/org.wso2.carbon.apimgt.rest.api.publisher/src/main/resources/publisher-api.yaml) of the API which is written using [swagger 2.0](http://swagger.io/) specification. 
 *
 * OpenAPI spec version: v1.0
 * Contact: architecture@wso2.com
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package org.wso2.carbon.apimgt.rest.integration.tests.publisher.model;

import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import org.wso2.carbon.apimgt.rest.integration.tests.publisher.model.EndpointConfigAttributes;

/**
 * EndpointConfig
 */

public class EndpointConfig {
  @JsonProperty("url")
  private String url = null;

  @JsonProperty("timeout")
  private String timeout = null;

  @JsonProperty("isPrimary")
  private Boolean isPrimary = null;

  @JsonProperty("attributes")
  private List<EndpointConfigAttributes> attributes = null;

  public EndpointConfig url(String url) {
    this.url = url;
    return this;
  }

   /**
   * Service url of the endpoint 
   * @return url
  **/
  @ApiModelProperty(example = "http://localhost:8280", value = "Service url of the endpoint ")
  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public EndpointConfig timeout(String timeout) {
    this.timeout = timeout;
    return this;
  }

   /**
   * Time out of the endpoint 
   * @return timeout
  **/
  @ApiModelProperty(example = "1000", value = "Time out of the endpoint ")
  public String getTimeout() {
    return timeout;
  }

  public void setTimeout(String timeout) {
    this.timeout = timeout;
  }

  public EndpointConfig isPrimary(Boolean isPrimary) {
    this.isPrimary = isPrimary;
    return this;
  }

   /**
   * Defines whether the endpoint is primary when used in fail over. 
   * @return isPrimary
  **/
  @ApiModelProperty(example = "true", value = "Defines whether the endpoint is primary when used in fail over. ")
  public Boolean getIsPrimary() {
    return isPrimary;
  }

  public void setIsPrimary(Boolean isPrimary) {
    this.isPrimary = isPrimary;
  }

  public EndpointConfig attributes(List<EndpointConfigAttributes> attributes) {
    this.attributes = attributes;
    return this;
  }

  public EndpointConfig addAttributesItem(EndpointConfigAttributes attributesItem) {
    if (this.attributes == null) {
      this.attributes = new ArrayList<EndpointConfigAttributes>();
    }
    this.attributes.add(attributesItem);
    return this;
  }

   /**
   * Get attributes
   * @return attributes
  **/
  @ApiModelProperty(value = "")
  public List<EndpointConfigAttributes> getAttributes() {
    return attributes;
  }

  public void setAttributes(List<EndpointConfigAttributes> attributes) {
    this.attributes = attributes;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    EndpointConfig endpointConfig = (EndpointConfig) o;
    return Objects.equals(this.url, endpointConfig.url) &&
        Objects.equals(this.timeout, endpointConfig.timeout) &&
        Objects.equals(this.isPrimary, endpointConfig.isPrimary) &&
        Objects.equals(this.attributes, endpointConfig.attributes);
  }

  @Override
  public int hashCode() {
    return Objects.hash(url, timeout, isPrimary, attributes);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class EndpointConfig {\n");
    
    sb.append("    url: ").append(toIndentedString(url)).append("\n");
    sb.append("    timeout: ").append(toIndentedString(timeout)).append("\n");
    sb.append("    isPrimary: ").append(toIndentedString(isPrimary)).append("\n");
    sb.append("    attributes: ").append(toIndentedString(attributes)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
  
}

