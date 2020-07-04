<%@ page contentType="text/html;charset=utf-8" %>
<html ng-app="app">
<head>
	<meta charset="UTF-8">
</head>
<body>

<div ng-controller="phoneController">
	<p>Название: {{phone.name}}</p>
	<p>Цена: {{phone.price}} $</p>
	<p>Производитель: {{phone.company.name}}</p>
</div>

<h2>Hello World</h2>
</body>
<script src="/test1/scripts/bundle.js"></script>
</html>