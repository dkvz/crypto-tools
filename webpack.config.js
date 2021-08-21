const HtmlWebpackPlugin = require('html-webpack-plugin')
const MiniCssExtractPlugin = require('mini-css-extract-plugin')
const path = require('path')

const minifyOptions = {
  removeComments: true,
  collapseWhitespace: true,
  removeAttributeQuotes: false
}

const config = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, './dist'),
    filename: 'bundle.js',
    clean: true
  },
  module: {
    rules: [
      {
        test: /\.p?css$/,
        use: [
          MiniCssExtractPlugin.loader,
          'css-loader', 'postcss-loader',
        ],
      }
    ]
  },
  plugins: [
    new MiniCssExtractPlugin({
      chunkFilename: 'styles.css'
    })
  ],
}

module.exports = (env, argv) => {
  // Hack we need to set NODE_ENV to production
  // or development. We could do it with the 
  // CLI in package.json but then that doesn't
  // play well with Windows.
  process.env.NODE_ENV = argv.mode === 'production' ? 
    'production' : 'development'

  config.plugins.push(new HtmlWebpackPlugin({
    template: './src/index.html',
    minify: (argv.mode === 'production') ? minifyOptions : false
  }))

  return config
}