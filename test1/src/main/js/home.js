//import 'bootstrap';
//import 'node_modules/bootstrap/dist/css/bootstrap.min.css';

import $ from 'jquery'
import 'bootstrap';


var angular=require('angular');
var ngModule=angular.module('app',[]);

ngModule.controller('CascadeCtrl',["$scope", function($scope) {
	$scope.menuWidth="w-25";
	$scope.contentWidth="w-75";
	$scope.menuDisplay="d-block";
	$scope.iframe="/test1/events";
	
	var flagMenuDisplay=true;
	
	var formCascade=$("#formCascade");
	var formHeader=$("#formHeader");
	var formBody=$("#formBody");
	
	var delta=formCascade.height()-formHeader.height();
	formBody.height(delta-1);
	
	$scope.menuClick=function(){
		if(flagMenuDisplay) {
			flagMenuDisplay=false;
			$scope.menuDisplay="d-none";
			$scope.contentWidth="w-100";
		} 
		else {
			flagMenuDisplay=true;
			$scope.menuDisplay="d-block";
			$scope.contentWidth="w-75";
			$scope.menuWidth="w-25";
		}
	}
	$scope.createEventClick=function(){
		$scope.iframe="/test1/create-event";
	}
	$scope.eventsClick=function(){
		$scope.iframe="/test1/events";
	}
	
}]);