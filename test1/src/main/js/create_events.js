
import $ from 'jquery'
import 'bootstrap';

var angular=require('angular');
var ngModule=angular.module('createEvent',[]);

ngModule.controller('CreateEventCtrl',["$scope","$http", function($scope,$http) {
	$scope.typeEvent="1";
	$("sa");
	$scope.createEvent=function(){
		var s=$scope;
		console.log(s.typeEvent,s.nameTask,s.descriptionTask,s.dueDateTask);
		var myData={
			typeEvent:s.typeEvent,
			nameTask:s.nameTask,
			descriptionTask:s.descriptionTask
		};
		
		$http.post(
			"/test1/create-task",
			myData,
			{
				headers: {'Content-Type': 'application/json','Accept':'application/json'}
			}
		).then(function(response) {
			console.log(response);
		},function(err){
			console.log("error:",err);
		});
		
		
	}
}]);