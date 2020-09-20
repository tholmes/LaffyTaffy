/*
 * Copyright Utah State University Research Foundation.
 * All rights reserved except as specified below.
 * This information is protected by a Non-Disclosure/Government Purpose
 * License Agreement and is authorized only for United States Federal
 * Government use.
 * This information may be subject to export control.
 */
(function () {
  "use strict";
  angular
    .module("login", [])
    .controller("loginCtrl", login);

  // http://stackoverflow.com/a/901144/1873715
  function getParameterByName(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
      results = regex.exec(location.search);
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
  }

  function login($scope, $http) {
    $http.get("/log/pki").then(function (response) {
      $scope.pkiEnabled = response.data.enabled;
    });

    function loginSuccess() {
      $scope.message = "Authenticated";
      $scope.type = "success";
      window.location.href = "/index.html";
    }

    function loginFailure(response) {
      $scope.loading = false;
      $scope.message = _.get(response, "data.error") || _.get(response, "data.message", "Authentication Failed");
    }

    $scope.userName = "";
    $scope.password = "";
    $scope.message = getParameterByName("message") || "";
    $scope.loading = false;
    $scope.type = "danger";
    $scope.submit = function () {
      $scope.loading = true;
      $http
        .post("/log/in", {
          username: $scope.userName,
          password: $scope.password
        })
        .then(loginSuccess)
        .catch(loginFailure);
    };

    $scope.pkiLogin = function () {
      $scope.loading = true;
      return $http.post("/log/in", { pki : true })
        .then(loginSuccess)
        .catch(loginFailure);
    };
  }
}());
