<%@ page contentType="text/html;charset=utf-8" %>
<html ng-app="app">
	<head>
		<meta charset="UTF-8">
		<link rel="stylesheet" href="/test1/styles/home.css">
		
	</head>
	<body> 
		<div id="formCascade" ng-controller="CascadeCtrl" class="container-fluid h-100" >
			<div class="row min-w-100 border-bottom" id="formHeader">
				<button type="button" class="btn btn-link" ng-click="menuClick()">
					<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABmJLR0QA/wD/AP+gvaeTAAAAKUlEQVRIiWNgGOqAkYGB4T8tLWCipeGjYBQMETCa0UbBKKADGM1oAw8A4D4DB6WZLegAAAAASUVORK5CYII="/>
				</button>
			</div>
			<div class="row" id="formBody">
					<div class="{{menuWidth}} {{menuDisplay}} border-right">
						<br/>
						<button type="button" class="btn btn-link" ng-click="eventsClick()">События</button> </br>
						<button type="button" class="btn btn-link" ng-click="createEventClick()">Создать событие</button>
					</div>
					<div class="{{contentWidth}}">
						<div class="overflow-auto">
							<iframe class="embed-responsive-item h-100 w-100 border-0" src="{{iframe}}" allowfullscreen></iframe>
						</div>
					</div>
					
			</div>
		</div>
	</body>
	<script src="/test1/scripts/home.js"></script>
</html>