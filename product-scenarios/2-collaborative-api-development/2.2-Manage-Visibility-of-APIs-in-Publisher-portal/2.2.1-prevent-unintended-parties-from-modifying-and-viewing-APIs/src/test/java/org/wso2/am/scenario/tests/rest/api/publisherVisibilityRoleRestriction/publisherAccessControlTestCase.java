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

import org.testng.annotations.AfterClass;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertTrue;

public class publisherAccessControlTestCase extends ScenarioTestBase {

    private APIPublisherRestClient apiPublisher;
    private String apiName;
    private String apiContext;
    private String apiVersion = "1.0.0";
    private String apiResource = "/find";
    private String apiVisibility = "restricted";
    private String tierCollection = "Gold,Bronze";
    private String backendEndPoint = "http://ws.cdyne.com/phoneverify/phoneverify.asmx";
    private String visibilityType = "publisher";
    private int count = 0;

    private String userName;
    private String password;
    private String publisherRole;
    private String creatorRole;
    private String creator;
    private String testUser;
    private String roleSet;

    private final String ADMIN_LOGIN_USERNAME = "admin";
    private final String ADMIN_PASSWORD = "admin";
    private final String DEVELOPER_USERNAME = "testUser";
    private final String DEVELOPER_PASSWORD = "test123";
    private static final String TENANT_DOMAIN = "testwso2.com";
    private static final String TENANT_LOGIN_ADMIN_USERNAME = "admin@testwso2.com";
    private static final String TENANT_LOGIN_ADMIN_PASSWORD = "admin123";


    Map<String, String> apiNames = new HashMap<>();
    List<String> userList = new ArrayList();
    List<String> roleList = new ArrayList();

    String userRole;

    @BeforeClass(alwaysRun = true)
    public void init() {
        apiPublisher = new APIPublisherRestClient(publisherURL);
    }

    @Test(description = "2.2.1.1", dataProvider = "UserTypeDataProvider",
    dataProviderClass = ScenarioDataProvider.class)
    public void testVisibilityOfAPIsInPublisherRestrictedByRoles(String type) throws Exception {
        apiName = "API" + count;
        apiContext = "/verify" + count;
        creator = "User_" + count;
        testUser = "User" + count;
        password = "password123$";
        publisherRole = "publisher" + count;
        count++;

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        if(type.equals("normalUser")) {
            createUserWithCreatorRole(creator , password, "admin", "admin");
            createRole("admin", "admin", publisherRole, permissionArray);
            createUser(testUser, password, new String[]{publisherRole}, ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
            APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, publisherRole, visibilityType,
                    apiVersion, apiResource, tierCollection, new URL(backendEndPoint));

            createAPI(apiRequest, creator);
            apiPublisher.login(testUser, password);
            getAPI(apiName, ADMIN_LOGIN_USERNAME);

        } else {
            addTenantAndActivate(ScenarioTestConstants.TENANT_WSO2, "admin", "admin");
            createUserWithCreatorRole(creator , password, "admin@w2.com", "admin");
            createRole("admin@w2.com", "admin", publisherRole, permissionArray);
            createUser(testUser, password, new String[]{publisherRole}, "admin@w2.com",
                    "admin");
            APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, publisherRole, visibilityType,
                    apiVersion, apiResource, tierCollection, new URL(backendEndPoint));

            createAPI(apiRequest,creator);
            apiPublisher.login(testUser + "@w2.com" , password);
            getAPI(apiName, "admin@w2.com");
        }

    }

    @Test(description = "2.2.1.2")
    public void testVisibilityInPublisherRestrictedByRolesWithSpace() throws Exception {

        apiName = "API";
        apiContext = "/verify" ;
        creator = "User";
        testUser = "User";
        password = "password123$";
        roleSet = "Role 1, Role2 ";
        publisherRole = "Role1";
        creatorRole = "Role2";
        count++;

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        createUserWithCreatorRole(creator , password, "admin", "admin");
        apiPublisher.login(creator, password);
        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, publisherRole, permissionArray);
        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, creatorRole, permissionArray);
        createUser(testUser, password, new String[]{ publisherRole,creatorRole },ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);

        APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, roleSet, visibilityType,
                apiVersion, apiResource, tierCollection, new URL(backendEndPoint));

        createAPI(apiRequest,creator);
        apiPublisher.login(testUser, password);
        getAPI(apiName, ADMIN_LOGIN_USERNAME);
    }




    @Test(description = "2.2.1.3")
    public void testVisibilityOfAPIsPublisherRestrictedByMultipleRoles() throws Exception {

        publisherRole = "NewRole1";
        creatorRole = "NewRole2";
        creator = "creator" ;
        userName = "MultipleRoleUser";
        password = "password123$";
        apiName = "RestAPI1";
        apiContext = "/Add";

        String[] permissionArray = new String[]{"/permission/admin/login",
                "/permission/admin/manage/api/publish"};

        createUserWithCreatorRole(creator , password, "admin", "admin");
        apiPublisher.login(creator, password);
        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, publisherRole, permissionArray);
        createRole(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD, creatorRole, permissionArray);
        createUser(userName, password, new String[]{creatorRole} , ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);

        String multipleRoles = publisherRole + "," + creatorRole;
        APIRequest apiRequest = new APIRequest(apiName, apiContext, apiVisibility, multipleRoles, visibilityType,
                apiVersion, apiResource, tierCollection, new URL(backendEndPoint));

        validateRoles(multipleRoles);
        createAPI(apiRequest,creator);
        apiPublisher.logout();
        apiPublisher.login(userName, password);
        getAPI(apiName, ADMIN_LOGIN_USERNAME);
    }




    private void validateRoles(String roles) throws APIManagerIntegrationTestException {

        HttpResponse checkValidationRole = apiPublisher.validateRoles(roles);
        assertTrue(checkValidationRole.getData().contains("true"));
        verifyResponse(checkValidationRole);
    }

    private void createAPI(APIRequest apiCreationRequest,String userName) throws APIManagerIntegrationTestException {

        apiPublisher.login(userName,password);
        HttpResponse apiCreationResponse = apiPublisher.addAPI(apiCreationRequest);
        verifyResponse(apiCreationResponse);
    }

    public void getAPI(String apiName,String provider) throws APIManagerIntegrationTestException {

        HttpResponse apiResponseGetAPI = apiPublisher.getAPI(apiName, provider, apiVersion);
        verifyResponse(apiResponseGetAPI);
        assertTrue(apiResponseGetAPI.getData().contains(apiName), apiName + " is not visible in publisher");
    }

    @AfterClass(alwaysRun = true)
    public void destroy() throws Exception {

        apiPublisher.login(ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
        apiPublisher.deleteAPI("RestAPI", apiVersion, ADMIN_LOGIN_USERNAME);
        apiPublisher.deleteAPI("RestAPI1", apiVersion, ADMIN_LOGIN_USERNAME);

        deleteUser("SubscriberUser", ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
        deleteRole("Health-Subscriber", ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
        deleteUser("MultipleRoleUser", ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
        deleteRole("NewRole1", ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
        deleteRole("NewRole2", ADMIN_LOGIN_USERNAME, ADMIN_PASSWORD);
    }



}



