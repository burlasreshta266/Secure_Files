export function captureKeystrokes(hid_input, bio_input, form){

    const timestamps = []
    const active = {}

    bio_input.addEventListener('keydown', (event) => {
        // make sure only alpha numeric characters are clicked
        if(!(/^[a-zA-Z0-9]$/.test(event.key))) return;
        const k = event.key.toLowerCase();
        
        if(active[k]) return;
        active[k] = {
            'key' : k,
            'dt' : Date.now()
        };
    })
    bio_input.addEventListener('keyup', (event) => {
        // make sure only alpha numeric characters are clicked
        if(!/^[a-zA-Z0-9]$/.test(event.key)) return;
        const k = event.key.toLowerCase();

        if(!active[k]) return;
        active[k].ut = Date.now();
        timestamps.push(active[k]);
        delete active[k];
    })
    form.addEventListener('submit', () => {
        hid_input.value = JSON.stringify(timestamps);

        // cleanup
        for (const k in active) delete active[k];
    })
}