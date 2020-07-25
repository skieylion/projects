import $ from 'jquery'
//import 'bootstrap/dist/css/bootstrap.min.css';
import 'metro4/build/css/metro-all.css';
//import 'metro4/build/css/metro-icons.css';
import 'metro4/build/js/metro.min.js';


$("#buttonRemove").on("click", function(e) {
	var table = Metro.getPlugin("#tableEvents", "table");
	var rowsSelected=table.getSelectedItems();
	for(var i=0;i<rowsSelected.length;i++) {
		var _id=rowsSelected[i][3];
		var url="./deleteTask";
		$.get(url,{id:String(_id)})
		.done(function(response){
			location.reload();
			//console.log(response);
		})
		.fail(function(err){
			console.log(err);
		});
	}
});


function _EventsTable() {
	
}

export default _EventsTable;