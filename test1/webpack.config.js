const path=require('path');
const webpack=require('webpack');
var MiniCssExtractPlugin=require('mini-css-extract-plugin');
const build=path.resolve(__dirname,'src/main/webapp/WEB-INF');


const home = {
	entry:'./src/main/js/home.js',
	output:{
		filename:'home.js',
		path:path.resolve(__dirname,'src/main/webapp/WEB-INF/scripts')
	},
	optimization: {
		// We no not want to minimize our code.
		minimize: false
	},
	module:{
		rules:[
			{
			    test: /\.less$/,
			    use:[ 'style-loader','css-loader','less-loader'] // compiles Less to CSS
			  },
			{
				test:/\.css$/,
				use:[
					{
						loader:MiniCssExtractPlugin.loader,
					},
					'css-loader',
				]
				
			}
			 
		]
	},
	plugins:[
		new MiniCssExtractPlugin(
			{
				filename:'../styles/home.css',
			}
		)
	]
}

const create_events = {
	entry:'./src/main/js/create_events.js',
	output:{
		filename:'create_events.js',
		path:path.resolve(__dirname,'src/main/webapp/WEB-INF/scripts')
	},
	optimization: {
		// We no not want to minimize our code.
		minimize: false
	},
	module:{
		rules:[
			{
			    test: /\.less$/,
			    use:[ 'style-loader','css-loader','less-loader'] // compiles Less to CSS
			  },
			{
				test:/\.css$/,
				use:[
					{
						loader:MiniCssExtractPlugin.loader,
					},
					'css-loader',
				]
				
			}
			 
		]
	},
	plugins:[
		new MiniCssExtractPlugin(
			{
				filename:'../styles/create_events.css',
			}
		)
	]
}

const events = {
	entry:'./src/main/js/events.js',
	output:{
		filename:'events.js',
		path:path.resolve(__dirname,'src/main/webapp/WEB-INF/scripts'),
		library:'EventsTable',
    	libraryTarget:'umd',
    	libraryExport:"default"
	},
	optimization: {
		// We no not want to minimize our code.
		minimize: false
	},
	module:{
		rules:[
			{
				test: /\.(png|jpg|gif|svg|ttf|woff)$/i,
				use: [
				  {
					loader: 'url-loader',
					options: {
					  limit: 999999
					}
				  }
				]
			},
			{
		        test: /\.js$/,
		        enforce: 'pre',
		        use: ['source-map-loader'],
		      },
			{
			    test: /\.less$/,
			    use:[ 'style-loader','css-loader','less-loader'] // compiles Less to CSS
			  },
			{
				test:/\.css$/,
				use:[
					{
						loader:MiniCssExtractPlugin.loader,
					},
					'css-loader',
				]
				
			}
			 
		]
	},
	plugins:[
		new MiniCssExtractPlugin(
			{
				filename:'../styles/events.css',
			}
		)
	]
}


module.exports = [home,events,create_events];