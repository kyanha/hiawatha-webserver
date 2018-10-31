<?xml version="1.0" ?>
<xsl:stylesheet version="1.1" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:output method="html" doctype-system="about:legacy-compat" />

<xsl:template match="/index">
<html>

<head>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><xsl:value-of select="hostname" /> : <xsl:value-of select="request_uri" /></title>
<style type="text/css">
	body {
		background-color:#ffffff;
		font-family:sans-serif;
		font-size:12px;
		padding:25px 100px;
	}

	h1 {
		font-size:200%;
		color:#6878e0;
		text-align:center;
	}

	h2 {
		font-size:150%;
	}

	h1, h2 {
		letter-spacing:5px;
		max-width:900px;
		margin:15px auto;
	}

	table {
		width:100%;
		max-width:900px;
		margin:0 auto;
		border-spacing:0;
		box-shadow:6px 12px 15px 5px #808080;
		border-radius:15px;
	}

	table th, table td {
		padding:10px 30px;
	}

	thead th {
		background-color:#6878e0;
		color:#ffffff;
		letter-spacing:1px;
		text-align:left;
		font-size:13px;
		font-weight:400;
	}
	thead th.filename {
		border-top-left-radius:15px;
	}

	tbody td {
		border-bottom:1px solid #e0e0e0;
	}
	tbody tr:hover td {
		background-color:#ffffe0;
		cursor:pointer;
	}
	tbody tr:nth-child(even) {
		background-color:#f8f8ff;
	}
	tbody tr:nth-child(odd) {
		background-color:#ffffff;
	}
	tbody td.size {
		text-align:right;
	}
	tbody td.dir {
    	background-image:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAABX1BMVEX39/dra2tsbGxtbW1ubm57e3t+fn5/f3+ua1Cua1G2cVO4dFS7eFW9e1a6fVe/f1e7f1i9g1m/hFnBgljDhVnFiFnGiVrHjFrDiF7HjV/IjFrIjFvJjlvKkFzLkVzMk13NlF3PlV3Oll7Pl17Rml/SnV/Pmmbfl2HTnWDUn2DUoGHVoWHWo2TZqGXZqWfRoGrToGvXqW/0rWn0t2z5tWv+uW3+vG7hrXT6zHitra2vr6+wsLCysrLJrZnLtZ/ivYbhvpDXvKrZvqn90oP33IP52oH/1orlxJPjw5nu15z45Y385pn56p3dxavjxqDjyKr/76j7763//aP05rry47z88LD89L3//77MzMzU1NTW1tbd3d399sf/+Mf48cv9+Mz9+c727dL9+dn//9v+/t3l5eXn5+fo6Ojp6en16+T48Ob9+uX//OX//uX+/up9W1D8+PX4+Pj5+fn///j///+gwhWcAAAAAXRSTlMAQObYZgAAAAFiS0dEAIgFHUgAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAHdElNRQfVAxgNNRYCF8YoAAAAr0lEQVR42mNgIAwcdDT1fdMQfD/37LxEA7touIBhXEpKSoiajLiYhCNYnVZ8AhQEC1imAgVUwzz1tDVUlORlpcUEbYFqVAJ1s6C6czL5rNIYlH20i5NiwMA/l5c1kkHBSyM5FAI8YnmYIhjkXFXCvSHAPoCbMYJBxkIpyBkCzN24gAKSxoouZqYgYKJuxAHU4iQkKiUmIszPy8PNxZnPFsWQbs3GwgwFLOw2GRh+BQApPielSWe5LQAAAABJRU5ErkJggg==);
	}
	tbody td.file {
		background-image:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAe1BMVEX///8WFhZAQEBLS0ldXV12dnaFhYWgoKCoqKitra27u7u8vLy9vb2+vr6/v7/AwMDBwcHCwsLDw8PExMTFxcXg4ODi4uLj4+Pk5OTl5eXm5ubn5+fo6Ojq6urr6+vs7Ozt7e3u7u7v7+/w8PDx8fH7+/v9/f3+/v4AAADSBF8OAAAAAXRSTlMAQObYZgAAAAFiS0dEAIgFHUgAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAAHdElNRQfVAxgOIR25LXasAAAAgklEQVR42kXQ2xaCIBCFYaLjKJXaAVDQMLXe/wnDYbP615qbb+YGhCCZI8HJD7c8qi8BJq6ZT0ky0H4nJYCIpvfzsN1kGLkQ7oCR1kIYbgmWgPoG8KJhPfG+AvQOXQE+rl2c7gJwbcqeAR2ljAK01lpjtNZFglopVZZF7Mjwfz5/wA+3tg7+aWT54QAAAABJRU5ErkJggg==);
	}
	tbody td.dir, tbody td.file {
		background-repeat:no-repeat;
		background-position:30px 8px;
		padding-left:55px;
	}
	tbody td.dir a, tbody td.file a {
		color:#4080ff;
	}

	tfoot td {
		background-color:#ececec;
	}
	tfoot td.totalsize {
		text-align:right;
		border-bottom-right-radius:15px;
	}

	a {
		text-decoration:none;
	}

	div.powered {
		margin-top:40px;
		text-align:center;
		color:#808080;
	}
	div.powered a {
		color:#80b0c0;
	}

	@media (max-width:767px) {
		body {
			padding:5px 25px;
		}

		h1, h2 {
			letter-spacing:1px;
		}
	}

	@media (min-width:640px) {
		thead th.timestamp {
			width:150px;
		}
		thead th.size {
			border-top-right-radius:15px;
			width:100px;
		}

		tfoot td.totalfiles {
			border-bottom-left-radius:15px;
		}
	}

	@media (max-width:639px) {
		table th, table td {
			display:block;
			min-height:12px;
			line-height:20px;
		}

		table tr.dir td.size {
			display:none;
		}

		table td:nth-child(2) {
			padding-left:55px;
		}

		thead th.filename {
			border-top-right-radius:15px;
		}

		tfoot td.totalsize {
			border-bottom-left-radius:15px;
		}

		table tfoot td:nth-child(2) {
			display:none;
		}
	}
</style>
</head>

<body>
<h1><xsl:value-of select="hostname" /></h1>
<h2><xsl:value-of select="request_uri" /></h2>
<table>
<thead>
<tr>
	<th class="filename">File name</th>
	<th class="timestamp">Timestamp</th>
	<th class="size">File size</th>
</tr>
</thead>
<tbody>
<xsl:for-each select="files/file">
<tr class="{@type}" onClick="javascript:window.location.href='{.}'">
	<td class="{@type}"><a href="{@url_encoded}"><xsl:value-of select="." /></a></td>
	<td><xsl:value-of select="@timestamp" /></td>
	<td class="size"><xsl:value-of select="@size" /></td>
</tr>
</xsl:for-each>
</tbody>
<tfoot>
<tr>
	<td class="totalfiles"><xsl:value-of select="count(files/file)" /> files</td>
	<td></td>
	<td class="totalsize"><xsl:value-of select="total_size" /></td>
</tr>
</tfoot>
</table>
<div class="powered">Powered by <a href="https://www.hiawatha-webserver.org/" target="_blank"><xsl:value-of select="software" /></a></div>
</body>

</html>
</xsl:template>

</xsl:stylesheet>
