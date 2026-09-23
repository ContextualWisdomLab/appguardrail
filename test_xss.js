const byCat = Object.create(null);
byCat['__proto__'] = (byCat['__proto__']||0)+1;
console.log(byCat);

const catRows = Object.entries(byCat).sort((a,b)=>b[1]-a[1]).map(([c,n])=>
    `<div class="r"><span class="name">${c}</span><span class="cnt">${n}</span></div>`).join('');
console.log(catRows);
