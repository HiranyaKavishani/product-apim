/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.am.scenario.tests.rest.api.publisherVisibilityRoleRestriction;

import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import org.wso2.am.scenario.test.common.APIPublisherRestClient;
import org.wso2.am.scenario.test.common.APIRequest;
import org.wso2.am.scenario.test.common.ScenarioDataProvider;
import org.wso2.am.scenario.test.common.ScenarioTestBase;
import org.wso2.am.scenario.test.common.ScenarioTestConstants;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;
import org.wso2.am.integration.test.utils.APIManagerIntegrationTestException;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertTrue;

public class PublisherAccessControlTestCase extends ScenarioTestBase {

    private APIPublisherRestClient apiPublisher;
    private String apiName;
    private String apiContext;
    private String apiVersion = "1.0.0";
    private String apiResource = "/find";
    private String apiVisibility = "restricted";
    private String tierCollection = "Gold,Bronze";
    private String backendEndPoint = "http://ws.cdyne.com/phoneverify/phoneverify.asmx";
    private String visibilityType = "publisher";
    private String password = "password123$";

    private String publisherRole;
    private String creatorRole;
    private String creator;
    private String testUser;
    private String creatorUsername;
    private String testUsername;
    private String adminUsername;
    private String roleSet;

    private final String ADMIN_LOGIN_USERNAME = "admin";
    private final String ADMIN_PASSWORD = "admin";
    private static final String TENANT_LOGIN_ADMIN_USERNAME = "admin@wso2.com";
    private static final String TENANT_USER = "tenantUser";
    private static final String NORMAL_USER = "normalUser";

    Map<String, String> apiNames = new HashMap<>();
    Map<String, String> userList = new HashMap<>();
    Map<String, String> roleList = new HashMap<>();
    private int count = 0;

    @BeforeClass(alwaysRun = true)
    public void init() {

        apiPublisher = new APIPublisherRestClient(publisherURL);
    }

    @Test(description = "2.2.1.1", dataProvider = "UserTypeDataProvider",
            dataProviderClass = ScenarioDataProvider.class)
    public void testVisibilityOfAPIsInPublisherRestrictedByRoles(String userType, String role) throws Exception {

        apiName = "API__" + count;
        apiContext = "/check" + count;
        creator = "User_" + count;
        testUser = "User" + count;
        publisherRole = "publisher" + count;
        count++;

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        if (userType.equals(TENANT_USER)) {
            addTenantAndActivate(ScenarioTestConstants.TENANT_WSO2, ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
            adminUsername = TENANT_LOGIN_ADMIN_USERNAME;
            creatorUsername = creator + "@" + ScenarioTestConstants.TENANT_WSO2;
            testUsername = testUser + "@" + ScenarioTestConstants.TENANT_WSO2;

        }
        if (userType.equals(NORMAL_USER)) {
            adminUsername = ADMIN_LOGIN_USERNAME;
            creatorUsername = creator;
            testUsername = testUser;
        }

        createRole(adminUsername, ADMIN_PASSWORD, publisherRole, permissionArray);
        createUser(creator, password, new String[]{"Internal/creator", publisherRole}, adminUsername, ADMIN_PASSWORD);

        APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, publisherRole, visibilityType,
                apiVersion, apiResource, tierCollection, new URL(backendEndPoint));
        apiPublisher.login(creatorUsername, password);
        createAPI(apiRequest);

        if (role.equals(ADMIN_LOGIN_USERNAME)) {
            createUser(testUser, password, new String[]{role}, adminUsername, ADMIN_PASSWORD);
        } else {
            createUser(testUser, password, new String[]{publisherRole}, adminUsername, ADMIN_PASSWORD);
        }

        apiPublisher.logout();
        apiPublisher.login(testUsername, password);
        getAPI(apiName, creatorUsername);
        apiNames.put(apiName, creatorUsername);
        roleList.put(publisherRole, adminUsername);
        userList.put(testUser, adminUsername);
        userList.put(creator, adminUsername);
    }

    @Test(description = "2.2.1.2")
    public void testVisibilityInPublisherRestrictedByRolesWithSpace() throws Exception {

        apiName = "API";
        apiContext = "/verify";
        creator = "creatorUser";
        testUser = "testUser";
        roleSet = "Role 1, Role2 ";
        publisherRole = "Role1";
        creatorRole = "Role2";

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, publisherRole, permissionArray);
        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, creatorRole, permissionArray);

        createUser(creator, password, new String[]{"Internal/creator", publisherRole, creatorRole}, ADMIN_LOGIN_USERNAME,
                ADMIN_PASSWORD);
        createUser(testUser, password, new String[]{publisherRole}, ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);

        APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, roleSet, visibilityType,
                apiVersion, apiResource, tierCollection, new URL(backendEndPoint));

        apiPublisher.login(creator, password);
        createAPI(apiRequest);
        apiPublisher.logout();
        apiPublisher.login(testUser, password);
        getAPI(apiName, creator);
        apiNames.put(apiName, creator);
        roleList.put(publisherRole, ADMIN_LOGIN_USERNAME);
        roleList.put(creatorRole, ADMIN_LOGIN_USERNAME);
        userList.put(testUser, ADMIN_LOGIN_USERNAME);
        userList.put(creator, ADMIN_LOGIN_USERNAME);
    }

    @Test(description = "2.2.1.3", dataProvider = "UserTypeDataProvider", dataProviderClass = ScenarioDataProvider.class)
    public void testVisibilityOfAPIsPublisherRestrictedByMultipleRoles(String userType, String role) throws Exception {

        publisherRole = "NewRole3" + count;
        creatorRole = "NewRole4" + count;
        creator = "creator" + count;
        testUser = "MultipleRoleUser" + count;
        apiName = "RestAPI1" + count;
        apiContext = "/Add" + count;
        count++;

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        if (userType.equals("tenantUser")) {
            addTenantAndActivate(ScenarioTestConstants.TENANT_WSO2, ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
            adminUsername = TENANT_LOGIN_ADMIN_USERNAME;
            creatorUsername = creator + "@" + ScenarioTestConstants.TENANT_WSO2;
            testUsername = testUser + "@" + ScenarioTestConstants.TENANT_WSO2;

        } else {
            adminUsername = ADMIN_LOGIN_USERNAME;
            creatorUsername = creator;
            testUsername = testUser;
        }

        createRole(adminUsername, ADMIN_PASSWORD, publisherRole, permissionArray);
        createRole(adminUsername, ADMIN_PASSWORD, creatorRole, permissionArray);
        createUser(creator, password, new String[]{"Internal/creator", publisherRole, creatorRole}, adminUsername,
                ADMIN_PASSWORD);

        String multipleRoles = publisherRole + "," + creatorRole;
        APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, multipleRoles, visibilityType,
                apiVersion, apiResource, tierCollection, new URL(backendEndPoint));

        apiPublisher.login(creatorUsername, password);

        validateRoles(multipleRoles);
        createAPI(apiRequest);

        if (role.equals(ADMIN_LOGIN_USERNAME)) {
            createUser(testUser, password, new String[]{role}, adminUsername, ADMIN_PASSWORD);
        } else {
            createUser(testUser, password, new String[]{publisherRole, creatorRole}, adminUsername, ADMIN_PASSWORD);
        }

        apiPublisher.logout();
        apiPublisher.login(testUsername, password);
        getAPI(apiName, creatorUsername);
        apiNames.put(apiName, creatorUsername);
        roleList.put(publisherRole, adminUsername);
        roleList.put(creatorRole, adminUsername);
        userList.put(testUser, adminUsername);
        userList.put(creator, adminUsername);
    }

    @Test(description = "2.2.1.4")
    public void testCreateAPIsInPublisherRestrictedByRoles() throws Exception {

        apiName = "API-" + count;
        apiContext = "/check" + count;
        creator = "User_" + count;
        testUser = "User" + count;
        publisherRole = "publishUser" + count;
        count++;

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, publisherRole, permissionArray);
        createUser(creator, password, new String[]{"Internal/creator", publisherRole}, ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);

        APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, publisherRole, visibilityType,
                apiVersion, apiResource, tierCollection, new URL(backendEndPoint));
        apiPublisher.login(creator, password);
        createAPI(apiRequest);
        apiNames.put(apiName, creator);
        roleList.put(publisherRole, ADMIN_LOGIN_USERNAME);
        userList.put(creator, ADMIN_LOGIN_USERNAME);
    }

    private void validateRoles(String roles) throws APIManagerIntegrationTestException {

        HttpResponse checkValidationRole = apiPublisher.validateRoles(roles);
        assertTrue(checkValidationRole.getData().contains("true"));
        verifyResponse(checkValidationRole);
    }

    private void createAPI(APIRequest apiCreationRequest) throws APIManagerIntegrationTestException {

        HttpResponse apiCreationResponse = apiPublisher.addAPI(apiCreationRequest);
        verifyResponse(apiCreationResponse);
    }

    public void getAPI(String apiName, String provider) throws APIManagerIntegrationTestException {

        HttpResponse apiResponseGetAPI = apiPublisher.getAPI(apiName, provider, apiVersion);
        verifyResponse(apiResponseGetAPI);
        assertTrue(apiResponseGetAPI.getData().contains(apiName), apiName + " is not visible in publisher");
    }

    @AfterTest(alwaysRun = true)
    public void destroy() throws Exception {

        for (Map.Entry<String, String> entry : apiNames.entrySet()) {
            String apiName = entry.getKey();
            String provider = entry.getValue();
            apiPublisher.login(provider, password);
            apiPublisher.deleteAPI(apiName, apiVersion, provider);
        }

        for (Map.Entry<String, String> entry : userList.entrySet()) {
            String user = entry.getKey();
            String admin = entry.getValue();
            deleteUser(user, admin, ADMIN_PASSWORD);
        }

        if (roleList.size() > 0) {
            for (Map.Entry<String, String> entry : roleList.entrySet()) {
                String role = entry.getKey();
                String admin = entry.getValue();
                deleteRole(role, admin, ADMIN_PASSWORD);
            }
        }
    }
}



